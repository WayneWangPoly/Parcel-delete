# -*- coding: utf-8 -*-
import os, re, json, time, base64, logging, requests, itertools, uuid
from typing import Optional, List
from flask import Flask, request, jsonify, Response

# Twilio
from twilio.twiml.messaging_response import MessagingResponse
from twilio.request_validator import RequestValidator

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("wa-bot-two-msg-twiml-only")

# ===== 基础配置（可用环境变量覆盖） =====
KEY = os.environ.get("AES_KEY", "1236987410000111").encode()
IV  = os.environ.get("AES_IV",  "1236987410000111").encode()
URL_BASE  = os.environ.get("API_BASE", "https://microexpress.com.au")
ENDPOINT  = os.environ.get("API_DELETE", "/smydriver/delete-sudo-parcel")
HEADERS   = {
    "Content-Type": "application/json;UTF-8",
    "User-Agent": "Mozilla/5.0",
    "Accept-Language": "en-AU,en;q=0.9"
}
DEFAULT_REASON  = "NOREASON"
DEFAULT_ADDRESS = "house"
HTTP_TIMEOUT    = 10
OCR_TIMEOUT     = 10
MAX_BATCH_SIZE  = 20
MAX_VARIANTS    = 8

# ===== Twilio 验签配置 =====
TWILIO_AUTH_TOKEN        = os.environ.get("TWILIO_AUTH_TOKEN",  "").strip()
VERIFY_TWILIO_SIGNATURE  = os.environ.get("VERIFY_TWILIO_SIGNATURE", "0") == "1"
OCR_API_KEY              = os.environ.get("OCR_API_KEY", "K87899142388957").strip()

# ===== 文本抽取辅助 =====
CHAR_REPL = {
    'А':'A','В':'B','С':'C','Е':'E','Н':'H','І':'I','Ј':'J','К':'K','М':'M','О':'O','Р':'P','Ѕ':'S','Т':'T','Х':'X','У':'Y',
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y'
}

def normalize_text(s: str) -> str:
    for k, v in CHAR_REPL.items():
        s = s.replace(k, v)
    return s

def fix_ocr(s: str) -> str:
    return normalize_text(s).upper()

def canon_barcode(raw: str) -> Optional[str]:
    s = fix_ocr(raw)
    m = re.match(r'^ME([0-9OIL]{3})([0-9O]{10})([A-Z0-9O]{3})$', s)
    if not m:
        return None
    series, mid10, last3 = m.groups()
    series = series.replace('I', '1').replace('L', '1').replace('O', '0')
    mid10  = mid10.replace('O', '0')
    if not (series.isdigit() and mid10.isdigit()):
        return None
    return f"ME{series}{mid10}{last3}"

def extract_ids(text: str) -> List[str]:
    t = fix_ocr(re.sub(r'\s+', '', text))
    cands = re.findall(r'ME[0-9OIL]{3}[0-9O]{10}[A-Z0-9O]{3}', t)
    out: List[str] = []
    for c in cands:
        cc = canon_barcode(c)
        if cc and cc not in out:
            out.append(cc)
    log.info(f"[extract] found {len(out)}: {out}")
    return out

# ===== AES & 后端调用 =====
def pkcs7_pad(b: bytes, bs=16) -> bytes:
    pad = bs - (len(b) % bs)
    return b + bytes([pad]) * pad

def make_data_field(payload: dict) -> str:
    from Crypto.Cipher import AES  # 延迟导入
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pkcs7_pad(json.dumps(payload, separators=(',', ':')).encode()))
    return base64.b64encode(ct).decode()

def post_delete(barcode: str, reason=DEFAULT_REASON, addr=DEFAULT_ADDRESS):
    try:
        body = {"data": make_data_field({
            "bar_code": barcode.strip().upper(),
            "reason_code": reason,
            "address_type": addr,
            "myme_timestamp": int(time.time() * 1000)
        })}
        url = URL_BASE + ENDPOINT
        for i in range(1, 3):
            r = requests.post(url, json=body, headers=HEADERS, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                try:
                    js = r.json()
                except Exception:
                    js = {"raw": r.text}
                return js.get("code") == 200, js
            time.sleep(0.4 * i)
        return False, {"error": f"http {r.status_code}", "text": r.text[:200]}
    except Exception as e:
        return False, {"error": f"{type(e).__name__}: {e}"}

def expand_tail(code: str) -> List[str]:
    head, tail = code[:-3], code[-3:]
    pos = [i for i, ch in enumerate(tail) if ch in ("O", "0")]
    if not pos:
        return [code]
    out = {code}
    limit = min(MAX_VARIANTS, 1 << len(pos))
    cnt = 0
    for bits in itertools.product([0, 1], repeat=len(pos)):
        tl = list(tail)
        for idx, b in enumerate(bits):
            tl[pos[idx]] = '0' if b == 0 else 'O'
        out.add(head + ''.join(tl))
        cnt += 1
        if cnt >= limit:
            break
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
        # WhatsApp 媒体 URL 必须带 Basic Auth
        account_sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
        auth_token  = TWILIO_AUTH_TOKEN
        r = requests.get(url, auth=(account_sid, auth_token), timeout=8)
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
            data={'apikey': OCR_API_KEY, 'language': 'eng', 'isOverlayRequired': False, 'OCREngine': 2},
            files={'file': ('image.jpg', img, 'image/jpeg')},
            timeout=OCR_TIMEOUT
        )
        if r.status_code != 200:
            log.warning(f"[ocr] http {r.status_code}")
            return None
        js = r.json()
        if js.get("IsErroredOnProcessing"):
            log.warning(f"[ocr] error {js.get('ErrorMessage')}")
            return None
        pr = js.get("ParsedResults", [])
        if pr:
            text = pr[0].get("ParsedText", "")
            log.info(f"[ocr] text len {len(text)}")
            return text
        return None
    except Exception as e:
        log.warning(f"[ocr] {e}")
        return None

def process_image(img: bytes) -> List[str]:
    text = ocr_space(img)
    return extract_ids(text or "") if text else []

# ===== Twilio 验签 =====
def verify_twilio_signature(req) -> bool:
    if not VERIFY_TWILIO_SIGNATURE or not TWILIO_AUTH_TOKEN:
        return True
    validator = RequestValidator(TWILIO_AUTH_TOKEN)
    proto = req.headers.get('X-Forwarded-Proto', req.scheme)
    host  = req.headers.get('X-Forwarded-Host') or req.headers.get('Host')
    path  = req.full_path if req.query_string else req.path
    url   = f"{proto}://{host}{path}".rstrip('?')
    params = req.form.to_dict(flat=True)
    sig    = req.headers.get("X-Twilio-Signature", "")
    ok = validator.validate(url, params, sig)
    if not ok:
        log.warning(f"[sig] failed url={url}")
    return ok

# ===== 健康检查 =====
@app.get("/api/whatsapp_bot")
def health():
    return jsonify({
      "status": "ok",
      "version": "two-msg-twiml-only-1.0",
      "verify_sig": VERIFY_TWILIO_SIGNATURE,
      "base": URL_BASE,
      "endpoint": ENDPOINT
    })

# 可选：专门给 outbound status 用（如果以后要在 Twilio Console 里配）
@app.post("/twilio/status")
def twilio_status():
    f = request.values
    sid    = f.get("MessageSid") or f.get("SmsSid")
    status = f.get("MessageStatus") or f.get("SmsStatus")
    err    = f.get("ErrorCode")
    emsg   = f.get("ErrorMessage")
    to_    = f.get("To")
    from_  = f.get("From")
    direction = "outbound" if (sid or "").startswith("SM") else "inbound"
    log.info(f"[status][{direction}] sid={sid} status={status} err={err} emsg={emsg} to={to_} from={from_}")
    return ("", 200)

# ===== 主 Webhook：TwiML 直接发“两条消息” =====
@app.post("/api/whatsapp_bot")
def webhook():
    # 打印原始请求，便于排查
    try:
        log.info(f"[raw] headers={dict(request.headers)}")
        log.info(f"[raw] form={request.form.to_dict(flat=False)}")
    except Exception:
        pass

    # 验签
    if not verify_twilio_signature(request):
        log.warning("[sig] verification failed -> 403")
        return ("", 403)

    form = request.values

    # ① 如果是 outbound 的 status callback（SM 开头 + 有 MessageStatus），直接 200 返回
    sid_any = form.get("MessageSid") or form.get("SmsSid") or ""
    has_status_field = bool(form.get("MessageStatus") or form.get("SmsStatus"))
    is_outbound_sid  = sid_any.startswith("SM")
    is_status_callback = has_status_field and is_outbound_sid

    if is_status_callback:
        sid    = sid_any
        status = form.get("MessageStatus") or form.get("SmsStatus")
        err    = form.get("ErrorCode")
        emsg   = form.get("ErrorMessage")
        to_    = form.get("To")
        from_  = form.get("From")
        log.info(f"[status][outbound] sid={sid} status={status} err={err} emsg={emsg} to={to_} from={from_}")
        return ("", 200)

    # ② 真正的入站 WhatsApp 消息
    from_number = form.get("From", "")
    nmed = int(form.get("NumMedia", 0))
    body = (form.get("Body") or "").strip()
    sid  = sid_any
    rid  = str(uuid.uuid4())[:8]
    log.info(f"[{rid}] IN sid={sid} from={from_number} media={nmed} body='{body[:100]}'")

    # ====== 开始处理：识别 ID + 删除 ======
    ids = extract_ids(body) if body else []
    stats: List[str] = []

    # 识别图片
    if nmed > 0:
        for i in range(nmed):
            mu = form.get(f"MediaUrl{i}", "")
            mt = form.get(f"MediaContentType{i}", "")
            if not mu or not (mt or "").startswith("image/"):
                stats.append(f"Image {i+1}: not an image")
                continue
            img = dl_media(mu)
            if not img:
                stats.append(f"Image {i+1}: download failed")
                continue
            before = len(ids)
            got = process_image(img)
            for g in got:
                if g not in ids:
                    ids.append(g)
            stats.append(f"Image {i+1}: {'found' if got else 'no IDs'} (+{len(ids)-before})")

    # ====== 组装 TwiML 回复：两条 Message ======
    resp = MessagingResponse()

    # 第一条：英文 ACK（你要求的）
    if nmed > 0 and body:
        ack = f"✅ Received your text and 🖼️ {nmed} image(s). Working on it…"
    elif nmed > 0:
        ack = f"🖼️ Received {nmed} image(s). Working on it…"
    elif body:
        ack = f"✅ Received your message. Working on it…"
    else:
        ack = "👋 Message received. Working on it…"
    resp.message(ack)

    # 第二条：根据不同情况返回结果
    if not ids:
        # 没有识别到任何包裹号
        resp.message("❌ No parcel IDs found.\n💡 Send a clear screenshot or type: ME176XXXXXXXXXXABC")
        return Response(str(resp), mimetype="application/xml")

    if len(ids) > MAX_BATCH_SIZE:
        preview = "\n".join([f"  • {x}" for x in ids[:5]])
        stattxt = "\n".join(stats) if stats else ""
        body2 = (
            f"⚠️ Too many IDs: {len(ids)} (max {MAX_BATCH_SIZE}).\n"
            f"{stattxt}\n\nFirst 5:\n{preview}\n...\nPlease split into smaller batches."
        )
        resp.message(body2)
        return Response(str(resp), mimetype="application/xml")

    # 有 ID，调删除接口
    succ: List[str] = []
    fail: List[str] = []
    used: dict[str, str] = {}

    for pid in ids:
        ok, res = delete_with_variants(pid)
        if ok:
            succ.append(pid)
            if res.get("used") and res["used"] != pid:
                used[pid] = res["used"]
        else:
            fail.append(pid)

    # 组装结果文本
    lines: List[str] = [f"📦 Total {len(ids)} | ✅ Deleted {len(succ)} | ❌ Failed {len(fail)}"]
    if stats:
        lines.append("")
        lines.append("📊 Recognition summary:")
        lines.append("\n".join(stats))
    if succ:
        lines.append("")
        lines.append(f"✅ Deleted ({len(succ)}):")
        show = succ if len(succ) <= 12 else succ[:12] + [f"... and {len(succ) - 12} more"]
        for s in show:
            note = f" (used {used[s]})" if s in used else ""
            lines.append(f"  • {s}{note}")
    if fail:
        lines.append("")
        lines.append(f"❌ Failed ({len(fail)}):")
        showf = fail if len(fail) <= 8 else fail[:8] + [f"... and {len(fail) - 8} more"]
        for f in showf:
            lines.append(f"  • {f}")

    resp.message("\n".join(lines))
    return Response(str(resp), mimetype="application/xml")
