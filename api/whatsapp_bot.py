# -*- coding: utf-8 -*-
import os, re, json, time, base64, logging, requests, itertools, uuid
from typing import Optional, List
from flask import Flask, request, jsonify, Response

# Twilio
from twilio.rest import Client as TwilioClient
from twilio.request_validator import RequestValidator
from twilio.base.exceptions import TwilioRestException
from twilio.twiml.messaging_response import MessagingResponse

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("wa-bot-two-msg")

# ===== 基础配置（可用环境变量覆盖） =====
KEY = os.environ.get("AES_KEY", "1236987410000111").encode()
IV  = os.environ.get("AES_IV",  "1236987410000111").encode()
URL_BASE  = os.environ.get("API_BASE", "https://microexpress.com.au")
ENDPOINT  = os.environ.get("API_DELETE", "/smydriver/delete-sudo-parcel")
HEADERS   = {"Content-Type": "application/json;UTF-8", "User-Agent": "Mozilla/5.0", "Accept-Language": "en-AU,en;q=0.9"}
DEFAULT_REASON  = "NOREASON"
DEFAULT_ADDRESS = "house"
HTTP_TIMEOUT    = 10
OCR_TIMEOUT     = 10
MAX_BATCH_SIZE  = 20
MAX_VARIANTS    = 8

# ===== Twilio 配置（不使用 Messaging Service） =====
TWILIO_ACCOUNT_SID   = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN    = os.environ.get("TWILIO_AUTH_TOKEN",  "").strip()
TWILIO_WHATSAPP_FROM = os.environ.get("TWILIO_WHATSAPP_FROM", "").strip()  # e.g. whatsapp:+15558432115
VERIFY_TWILIO_SIGNATURE = os.environ.get("VERIFY_TWILIO_SIGNATURE", "0") == "1"
OCR_API_KEY = os.environ.get("OCR_API_KEY", "K87899142388957").strip()
STATUS_CALLBACK_URL = os.environ.get("STATUS_CALLBACK_URL", "").strip()    # 建议 https://<域名>/api/whatsapp_bot 或 /twilio/status

twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN) else None

# ===== 文本抽取辅助 =====
CHAR_REPL = {
    'А':'A','В':'B','С':'C','Е':'E','Н':'H','І':'I','Ј':'J','К':'K','М':'M','О':'O','Р':'P','Ѕ':'S','Т':'T','Х':'X','У':'Y',
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y'
}

def normalize_text(s: str) -> str:
    for k,v in CHAR_REPL.items():
        s = s.replace(k,v)
    return s

def fix_ocr(s: str) -> str:
    return normalize_text(s).upper()

def canon_barcode(raw: str) -> Optional[str]:
    s = fix_ocr(raw)
    m = re.match(r'^ME([0-9OIL]{3})([0-9O]{10})([A-Z0-9O]{3})$', s)
    if not m: return None
    series, mid10, last3 = m.groups()
    series = series.replace('I','1').replace('L','1').replace('O','0')
    mid10  = mid10.replace('O','0')
    if not (series.isdigit() and mid10.isdigit()):
        return None
    return f"ME{series}{mid10}{last3}"

def extract_ids(text: str) -> List[str]:
    t = fix_ocr(re.sub(r'\s+','', text))
    cands = re.findall(r'ME[0-9OIL]{3}[0-9O]{10}[A-Z0-9O]{3}', t)
    out = []
    for c in cands:
        cc = canon_barcode(c)
        if cc and cc not in out:
            out.append(cc)
    log.info(f"[extract] found {len(out)}: {out}")
    return out

# ===== AES & 后端调用 =====
def pkcs7_pad(b: bytes, bs=16) -> bytes:
    pad = bs - (len(b) % bs)
    return b + bytes([pad])*pad

def make_data_field(payload: dict) -> str:
    from Crypto.Cipher import AES  # 延迟导入，避免无库导入期崩
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pkcs7_pad(json.dumps(payload, separators=(',',':')).encode()))
    return base64.b64encode(ct).decode()

def post_delete(barcode: str, reason=DEFAULT_REASON, addr=DEFAULT_ADDRESS):
    try:
        body = {"data": make_data_field({
            "bar_code": barcode.strip().upper(),
            "reason_code": reason,
            "address_type": addr,
            "myme_timestamp": int(time.time()*1000)
        })}
        url = URL_BASE + ENDPOINT
        for i in range(1,3):
            r = requests.post(url, json=body, headers=HEADERS, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                try:
                    js = r.json()
                except Exception:
                    js = {"raw": r.text}
                return js.get("code")==200, js
            time.sleep(0.4*i)
        return False, {"error": f"http {r.status_code}", "text": r.text[:200]}
    except Exception as e:
        return False, {"error": f"{type(e).__name__}: {e}"}

def expand_tail(code: str) -> List[str]:
    head, tail = code[:-3], code[-3:]
    pos = [i for i,ch in enumerate(tail) if ch in ("O","0")]
    if not pos: return [code]
    out = {code}
    limit = min(MAX_VARIANTS, 1<<len(pos))
    cnt = 0
    for bits in itertools.product([0,1], repeat=len(pos)):
        tl = list(tail)
        for idx, b in enumerate(bits):
            tl[pos[idx]] = '0' if b==0 else 'O'
        out.add(head+''.join(tl)); cnt+=1
        if cnt>=limit: break
    return list(out)

def delete_with_variants(code: str):
    tried = []
    for cand in expand_tail(code):
        ok, res = post_delete(cand)
        tried.append((cand, ok))
        if ok:
            return True, {"used": cand, "result": res}
    return False, {"tried": tried}

# ===== 媒体 & OCR =====
def dl_media(url: str) -> Optional[bytes]:
    try:
        r = requests.get(url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), timeout=8)
        if r.status_code == 200:
            log.info(f"[media] {len(r.content)} bytes")
            return r.content
        log.warning(f"[media] http {r.status_code}")
    except Exception as e:
        log.warning(f"[media] {e}")
    return None

def ocr_space(img: bytes) -> Optional[str]:
    try:
        r = requests.post(
            "https://api.ocr.space/parse/image",
            data={'apikey': OCR_API_KEY, 'language':'eng', 'isOverlayRequired': False, 'OCREngine':2},
            files={'file': ('image.jpg', img, 'image/jpeg')},
            timeout=OCR_TIMEOUT
        )
        if r.status_code!=200:
            log.warning(f"[ocr] http {r.status_code}")
            return None
        js = r.json()
        if js.get("IsErroredOnProcessing"):
            log.warning(f"[ocr] error {js.get('ErrorMessage')}")
            return None
        pr = js.get("ParsedResults", [])
        if pr:
            text = pr[0].get("ParsedText","")
            log.info(f"[ocr] text len {len(text)}")
            return text
        return None
    except Exception as e:
        log.warning(f"[ocr] {e}")
        return None

def process_image(img: bytes) -> List[str]:
    text = ocr_space(img)
    return extract_ids(text or "") if text else []

# ===== 工具函数 =====
def normalize_wa(num: str) -> str:
    """确保号码是 whatsapp:+E164；已带前缀则原样。"""
    num = (num or "").strip()
    if not num:
        return num
    return num if num.startswith("whatsapp:") else f"whatsapp:{num}"

def verify_twilio_signature(req) -> bool:
    if not VERIFY_TWILIO_SIGNATURE or not TWILIO_AUTH_TOKEN:
        return True
    validator = RequestValidator(TWILIO_AUTH_TOKEN)
    # 反代下使用外部可见 URL
    proto = req.headers.get('X-Forwarded-Proto', req.scheme)
    host  = req.headers.get('X-Forwarded-Host') or req.headers.get('Host')
    path  = req.full_path if req.query_string else req.path
    url   = f"{proto}://{host}{path}".rstrip('?')
    params= req.form.to_dict(flat=True)
    sig   = req.headers.get("X-Twilio-Signature", "")
    ok = validator.validate(url, params, sig)
    if not ok: log.warning(f"[sig] failed url={url}")
    return ok

# ===== 发送（强制回入站 From；不用 Messaging Service） =====
def send_text(to_whatsapp: str, body: str, inbound_from_ctx: str = ""):
    """强制把消息发回入站 From（用户号码）。"""
    if not twilio_client:
        log.warning("[twilio] REST client not configured")
        return
    try:
        def norm(num: str) -> str:
            num = (num or "").strip()
            return num if num.startswith("whatsapp:") else f"whatsapp:{num}" if num else num

        to_final   = norm(inbound_from_ctx) or norm(to_whatsapp)
        from_final = norm(TWILIO_WHATSAPP_FROM)

        if not to_final:
            log.error("[twilio] empty recipient (no inbound_from_ctx and no to)")
            return
        if not from_final:
            log.error("[twilio] Missing TWILIO_WHATSAPP_FROM")
            return
        if to_final == from_final:
            log.error(f"[twilio] to==from ({to_final}). Refuse to send to ourselves.")
            return

        kwargs = {"to": to_final, "from_": from_final, "body": body}
        if STATUS_CALLBACK_URL:
            kwargs["status_callback"] = STATUS_CALLBACK_URL

        log.info(f"[twilio] creating message to={kwargs['to']} from={kwargs['from_']} body_len={len(body)}")
        msg = twilio_client.messages.create(**kwargs)
        log.info(f"[twilio] sent sid={msg.sid} to={kwargs['to']} from={kwargs['from_']}")
    except TwilioRestException as e:
        log.error(f"[twilio] status={getattr(e,'status',None)} code={getattr(e,'code',None)} msg={getattr(e,'msg',str(e))}")
    except Exception as e:
        log.error(f"[twilio] {e}")

# ===== 健康检查 =====
@app.get("/api/whatsapp_bot")
def health():
    return jsonify({
        "status":"ok",
        "version":"two-msg-ack-first-1.0",
        "twilio_from": TWILIO_WHATSAPP_FROM or "(none)",
        "verify_sig": VERIFY_TWILIO_SIGNATURE,
        "base": URL_BASE,
        "endpoint": ENDPOINT,
        "status_callback": STATUS_CALLBACK_URL or "(none)"
    })

# （可选）单独的状态回执端点；也可以只用 /api/whatsapp_bot
@app.post("/twilio/status")
def twilio_status():
    f = request.values
    sid    = f.get("MessageSid") or f.get("SmsSid")
    status = f.get("MessageStatus") or f.get("SmsStatus")
    err    = f.get("ErrorCode")
    emsg   = f.get("ErrorMessage")
    to_    = f.get("To"); from_ = f.get("From")
    direction = "outbound" if (sid or "").startswith("SM") else "inbound"
    log.info(f"[status][{direction}] sid={sid} status={status} err={err} emsg={emsg} to={to_} from={from_}")
    return ("", 200)

# ===== 主 Webhook（入站 + 状态回执同一路径；TwiML 先ACK） =====
@app.post("/api/whatsapp_bot")
def webhook():
    # 原始入参日志（即使验签失败也能看到）
    try:
        log.info(f"[raw] headers={dict(request.headers)}")
        log.info(f"[raw] form={request.form.to_dict(flat=False)}")
    except Exception:
        pass

    # 验签（可关闭）
    if not verify_twilio_signature(request):
        log.warning("[sig] verification failed -> 403")
        return ("", 403)

    form = request.values

    # ① Twilio 消息状态回执
    if form.get("MessageStatus") or form.get("SmsStatus"):
        sid    = form.get("MessageSid") or form.get("SmsSid")
        status = form.get("MessageStatus") or form.get("SmsStatus")
        err    = form.get("ErrorCode")
        emsg   = form.get("ErrorMessage")
        to_    = form.get("To"); from_ = form.get("From")
        direction = "outbound" if (sid or "").startswith("SM") else "inbound"
        log.info(f"[status][{direction}] sid={sid} status={status} err={err} emsg={emsg} to={to_} from={from_}")
        return ("", 200)

    # ② 入站消息
    inbound_from = normalize_wa(form.get("From",""))  # 发消息的用户
    nmed = int(form.get("NumMedia", 0))
    body = (form.get("Body") or "").strip()
    sid  = form.get("MessageSid","") or form.get("SmsSid","")
    rid  = str(uuid.uuid4())[:8]
    log.info(f"[{rid}] IN sid={sid} from={inbound_from} media={nmed} body='{body[:100]}'")

    # —— TwiML 先 ACK（必达）——
    if nmed > 0 and body:
        ack = f"✅ Received your text and 🖼️ {nmed} image(s). Working on it…"
    elif nmed > 0:
        ack = f"🖼️ Received {nmed} image(s). Working on it…"
    elif body:
        ack = f"✅ Received your message. Working on it…"
    else:
        ack = "👋 Message received. Working on it…"
    twiml = MessagingResponse()
    twiml.message(ack)
    ack_xml = str(twiml)

    # —— 识别 + 删除，完成后用 REST 回结果 —— 
    try:
        ids = extract_ids(body) if body else []
        stats = []
        if nmed>0:
            for i in range(nmed):
                mu = form.get(f"MediaUrl{i}", "")
                mt = form.get(f"MediaContentType{i}", "")
                if not mu or not (mt or "").startswith("image/"):
                    stats.append(f"Image {i+1}: not an image"); continue
                img = dl_media(mu)
                if not img:
                    stats.append(f"Image {i+1}: download failed"); continue
                before = len(ids)
                got = process_image(img)
                for g in got:
                    if g not in ids: ids.append(g)
                stats.append(f"Image {i+1}: {'found' if got else 'no IDs'} (+{len(ids)-before})")

        if not ids:
            send_text(inbound_from, "❌ No parcel IDs found.\n💡 Send a clear screenshot or type: ME176XXXXXXXXXXABC",
                      inbound_from_ctx=inbound_from)
            return Response(ack_xml, mimetype="application/xml")

        if len(ids) > MAX_BATCH_SIZE:
            preview = "\n".join([f"  • {x}" for x in ids[:5]])
            stattxt = "\n".join(stats) if stats else ""
            send_text(
                inbound_from,
                f"⚠️ Too many IDs: {len(ids)} (max {MAX_BATCH_SIZE}).\n{stattxt}\n\nFirst 5:\n{preview}\n...\nPlease split into smaller batches.",
                inbound_from_ctx=inbound_from
            )
            return Response(ack_xml, mimetype="application/xml")

        succ, fail, used = [], [], {}
        for pid in ids:
            ok, res = delete_with_variants(pid)
            if ok:
                succ.append(pid)
                if res.get("used") and res["used"] != pid:
                    used[pid] = res["used"]
            else:
                fail.append(pid)

        lines = [f"📦 Total {len(ids)} | ✅ Deleted {len(succ)} | ❌ Failed {len(fail)}"]
        if stats:
            lines.append(""); lines.append("📊 Recognition summary:"); lines.append("\n".join(stats))
        if succ:
            lines.append(""); lines.append(f"✅ Deleted ({len(succ)}):")
            show = succ if len(succ)<=12 else succ[:12] + [f"... and {len(succ)-12} more"]
            for s in show:
                note = f" (used {used[s]})" if s in used else ""
                lines.append(f"  • {s}{note}")
        if fail:
            lines.append(""); lines.append(f"❌ Failed ({len(fail)}):")
            showf = fail if len(fail)<=8 else fail[:8] + [f"... and {len(fail)-8} more"]
            for f in showf:
                lines.append(f"  • {f}")

        send_text(inbound_from, "\n".join(lines), inbound_from_ctx=inbound_from)
        return Response(ack_xml, mimetype="application/xml")
    except Exception as e:
        log.exception(f"[{rid}] pipeline error: {e}")
        return Response(ack_xml, mimetype="application/xml")
