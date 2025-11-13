# -*- coding: utf-8 -*-
import os, re, json, time, base64, logging, requests, itertools, uuid
from typing import Optional, List
from flask import Flask, request, jsonify, Response

from twilio.twiml.messaging_response import MessagingResponse
from twilio.request_validator import RequestValidator

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("wa-bot-two-msg-twiml-only")

# ===== 基础配置 =====
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

TWILIO_ACCOUNT_SID       = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN        = os.environ.get("TWILIO_AUTH_TOKEN",  "").strip()
VERIFY_TWILIO_SIGNATURE  = os.environ.get("VERIFY_TWILIO_SIGNATURE", "0") == "1"
OCR_API_KEY              = os.environ.get("OCR_API_KEY", "K87899142388957").strip()

# ===== 文本归一化 & ID 解析 =====
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

def canon_barcode_loose(raw: str) -> Optional[str]:
    """
    更宽松的规范化：
    - 只要求以 ME 开头，总长度 >= 18
    - 结构：ME + 3(系列) + 10(数字) + 3(任意字母数字)
    - 系列和中间 10 位允许 I/L/O，并纠正为 1/1/0
    """
    s = fix_ocr(raw)
    if not s.startswith("ME"):
        return None
    core = s[2:]
    if len(core) < 16:     # 3 + 10 + 3 = 16
        return None

    series = core[:3]
    mid10  = core[3:13]
    last3  = core[13:16]

    # 纠错：I/L/O -> 1/1/0
    series = series.replace("I", "1").replace("L", "1").replace("O", "0")
    mid10  = mid10.replace("O", "0").replace("I", "1").replace("L", "1")

    if not (series.isdigit() and mid10.isdigit()):
        return None

    return f"ME{series}{mid10}{last3}"

def extract_ids(text: str) -> List[str]:
    """
    从文本中提取 ME 编号：
    - 去掉所有空白
    - 先找 ME + 16~20 个字母数字 的候选
    - 再用 canon_barcode_loose 做规范化 + 去重
    """
    raw = text or ""
    compact = re.sub(r'\s+', '', raw)
    t = fix_ocr(compact)

    log.info(f"[extract] raw='{raw[:100]}'")
    log.info(f"[extract] norm='{t[:100]}'")

    # 宽松候选：以 ME 开头，长度够长
    candidates = re.findall(r'ME[0-9A-Z]{16,20}', t)
    log.info(f"[extract] candidates={candidates}")

    out: List[str] = []
    for c in candidates:
        cc = canon_barcode_loose(c)
        if cc and cc not in out:
            out.append(cc)

    log.info(f"[extract] found {len(out)} IDs: {out}")
    return out

# ===== AES & 后端删除 =====
def pkcs7_pad(b: bytes, bs=16) -> bytes:
    pad = bs - (len(b) % bs)
    return b + bytes([pad]) * pad

def make_data_field(payload: dict) -> str:
    from Crypto.Cipher import AES
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

# ===== 媒体 / QR / OCR =====
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

def decode_qr_goqr(img: bytes) -> Optional[str]:
    try:
        r = requests.post(
            "https://api.qrserver.com/v1/read-qr-code/",
            files={'file': ('image.jpg', img, 'image/jpeg')},
            timeout=10
        )
        if r.status_code != 200:
            log.warning(f"[qr] http {r.status_code}")
            return None
        js = r.json()
        if not js or not isinstance(js, list):
            return None
        symbols = js[0].get("symbol", [])
        if not symbols:
            return None
        data = symbols[0].get("data")
        if not data:
            return None
        log.info(f"[qr] data='{data[:100]}'")
        ids = extract_ids(data)
        return ids[0] if ids else None
    except Exception as e:
        log.warning(f"[qr] {e}")
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
    # 1️⃣ 先尝试二维码
    qr_id = decode_qr_goqr(img)
    if qr_id:
        log.info(f"[image] QR hit: {qr_id}")
        return [qr_id]

    # 2️⃣ QR 没中，再 OCR
    text = ocr_space(img)
    if not text:
        return []
    return extract_ids(text)

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
        "version": "two-msg-twiml-loose-1.0",
        "verify_sig": VERIFY_TWILIO_SIGNATURE,
        "base": URL_BASE,
        "endpoint": ENDPOINT
    })

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

# ===== 主 Webhook =====
@app.post("/api/whatsapp_bot")
def webhook():
    try:
        log.info(f"[raw] headers={dict(request.headers)}")
        log.info(f"[raw] form={request.form.to_dict(flat=False)}")
    except Exception:
        pass

    if not verify_twilio_signature(request):
        log.warning("[sig] verification failed -> 403")
        return ("", 403)

    form = request.values

    # 识别并忽略 outbound status callback
    sid_any = form.get("MessageSid") or form.get("SmsSid") or ""
    has_message_status = bool(form.get("MessageStatus"))  # 只看 MessageStatus，避免误杀 inbound
    is_outbound_sid  = sid_any.startswith("SM")
    is_status_callback = has_message_status and is_outbound_sid

    if is_status_callback:
        sid    = sid_any
        status = form.get("MessageStatus")
        err    = form.get("ErrorCode")
        emsg   = form.get("ErrorMessage")
        to_    = form.get("To")
        from_  = form.get("From")
        log.info(f"[status][outbound] sid={sid} status={status} err={err} emsg={emsg} to={to_} from={from_}")
        return ("", 200)

    # ===== 入站消息 =====
    from_number = form.get("From", "")
    nmed = int(form.get("NumMedia", 0))
    body = (form.get("Body") or "").strip()
    sid  = sid_any
    rid  = str(uuid.uuid4())[:8]
    log.info(f"[{rid}] IN sid={sid} from={from_number} media={nmed} body='{body[:100]}'")

    ids: List[str] = []
    stats: List[str] = []

    # 文本先抽
    if body:
        ids = extract_ids(body)

    # 图片再抽
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

    # ===== TwiML 两条消息 =====
    resp = MessagingResponse()

    # 第一条：ACK
    if nmed > 0 and body:
        ack = f"✅ Received your text and 🖼️ {nmed} image(s). Working on it…"
    elif nmed > 0:
        ack = f"🖼️ Received {nmed} image(s). Working on it…"
    elif body:
        ack = f"✅ Received your message. Working on it…"
    else:
        ack = "👋 Message received. Working on it…"
    resp.message(ack)

    # 第二条：结果
    if not ids:
        # 把 stats 也发回去，方便你调试
        extra = ("\n\n📊 Image summary:\n" + "\n".join(stats)) if stats else ""
        resp.message("❌ No parcel IDs found.\n💡 Send a clear screenshot or type: ME176XXXXXXXXXXABC" + extra)
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

    # 调删除接口
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
