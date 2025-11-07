# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client as TwilioClient
from twilio.request_validator import RequestValidator
from twilio.base.exceptions import TwilioRestException

import re, json, time, base64, logging, requests, os, itertools, uuid, threading
from Crypto.Cipher import AES
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from typing import Optional, List

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("wa-bot")

# ========== Config ==========
KEY = b"1236987410000111"
IV  = b"1236987410000111"
URL_BASE = "https://microexpress.com.au"
ENDPOINT = "/smydriver/delete-sudo-parcel"
HEADERS = {
    "Content-Type": "application/json;UTF-8",
    "User-Agent": "Mozilla/5.0",
    "Accept-Language": "en-AU,en;q=0.9"
}
DEFAULT_REASON = "NOREASON"
DEFAULT_ADDRESS = "house"
TIMEOUT = 15
MAX_BATCH_SIZE = 20
MAX_VARIANTS_PER_ID = 8

# Env
TWILIO_ACCOUNT_SID      = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN       = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_FROM    = "whatsapp:+15558432115"
MESSAGING_SERVICE_SID   = os.environ.get('MESSAGING_SERVICE_SID', '').strip() # optional
VERIFY_TWILIO_SIGNATURE = os.environ.get('VERIFY_TWILIO_SIGNATURE', '0') == '1'
ASYNC_MODE              = os.environ.get('ASYNC_MODE', '1') == '1'
OCR_API_KEY             = os.environ.get('OCR_API_KEY', 'K87899142388957').strip()

twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN) else None
POOL = ThreadPoolExecutor(max_workers=int(os.environ.get("WORKERS", "8")))

# ========== Dedup (MessageSid / Image hash, hooks ready) ==========
class TTLDict(OrderedDict):
    def __init__(self, ttl_seconds=86400, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ttl = ttl_seconds
        self.lock = threading.Lock()
    def set(self, k, v=True):
        with self.lock:
            now = time.time()
            super().__setitem__(k, now + self.ttl)
            # cleanup
            for key, exp in list(self.items()):
                if exp < now:
                    super().__delitem__(key)
    def has(self, k):
        with self.lock:
            exp = self.get(k)
            if not exp:
                return False
            if exp < time.time():
                try: super().__delitem__(key)
                except: pass
                return False
            return True

RECENT_SIDS   = TTLDict(ttl_seconds=24*3600)  # 24h
RECENT_IMAGES = TTLDict(ttl_seconds=3600)     # 1h (hash hooks预留，当前未启用)

# ========== Char replacements & extraction ==========
CHAR_REPLACEMENTS = {
    'А':'A','В':'B','С':'C','Е':'E','Н':'H','І':'I','Ј':'J','К':'K','М':'M','О':'O','Р':'P','Ѕ':'S','Т':'T','Х':'X','У':'Y',
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y'
}

def normalize_text(text: str) -> str:
    for k, v in CHAR_REPLACEMENTS.items():
        text = text.replace(k, v)
    return text

def fix_ocr_confusion(text: str) -> str:
    return normalize_text(text).upper()

def canonicalize_barcode(raw: str) -> Optional[str]:
    s = fix_ocr_confusion(raw)
    m = re.match(r'^ME([0-9OIL]{3})([0-9O]{10})([A-Z0-9O]{3})$', s)
    if not m:
        return None
    series, mid10, last3 = m.groups()
    series = series.replace('I','1').replace('L','1').replace('O','0')
    mid10  = mid10.replace('O','0')
    if not (series.isdigit() and mid10.isdigit()):
        return None
    return f"ME{series}{mid10}{last3}"

def smart_extract_parcel_id(text: str) -> List[str]:
    text = fix_ocr_confusion(text)
    text = re.sub(r'\s+', '', text)
    logger.info(f"[extract] sample: {text[:160]}...")
    candidates = re.findall(r'ME[0-9OIL]{3}[0-9O]{10}[A-Z0-9O]{3}', text)
    found = []
    for c in candidates:
        canon = canonicalize_barcode(c)
        if canon and canon not in found:
            found.append(canon)
    logger.info(f"[extract] found {len(found)}: {found}")
    return found

# ========== Crypto & HTTP ==========
def pkcs7_pad(b: bytes, block_size=16) -> bytes:
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len

def make_data_field(payload_obj: dict) -> str:
    plaintext = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return base64.b64encode(ct).decode('ascii')

def http_post_json_with_retries(url: str, json_body: dict, headers: dict, timeout: int, max_retry=3):
    last = None
    for i in range(1, max_retry+1):
        try:
            r = requests.post(url, json=json_body, headers=headers, timeout=timeout)
            if r.status_code == 200:
                return True, r
            logger.warning(f"[POST RETRY {i}] HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            last = e
            logger.warning(f"[POST RETRY {i}] exception: {repr(e)}")
        time.sleep(0.6 * i)
    return False, last or RuntimeError("post failed")

def delete_parcel_once(barcode: str, reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS):
    try:
        payload = {
            "bar_code": barcode.strip().upper(),
            "reason_code": reason_code,
            "address_type": address_type,
            "myme_timestamp": int(time.time() * 1000)
        }
        body = {"data": make_data_field(payload)}
        url  = URL_BASE + ENDPOINT
        ok, resp = http_post_json_with_retries(url, body, HEADERS, TIMEOUT, max_retry=2)
        if ok:
            try:
                result = resp.json()
            except Exception:
                result = {"raw": resp.text}
            return result.get('code') == 200, result
        else:
            return False, {"error": str(resp)}
    except Exception as e:
        return False, {"error": str(e)}

def expand_last3_variants(code: str) -> List[str]:
    head, tail = code[:-3], code[-3:]
    pos = [i for i, ch in enumerate(tail) if ch in ('O','0')]
    if not pos:
        return [code]
    variants = {code}
    limit = min(MAX_VARIANTS_PER_ID, 1 << len(pos))
    cnt = 0
    for bits in itertools.product([0,1], repeat=len(pos)):
        tl = list(tail)
        for idx, bit in enumerate(bits):
            tl[pos[idx]] = '0' if bit == 0 else 'O'
        variants.add(head + ''.join(tl))
        cnt += 1
        if cnt >= limit: break
    return list(variants)

def delete_parcel_with_variants_retry(code: str, reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS):
    tried = []
    for cand in expand_last3_variants(code):
        for attempt in range(1, 4):  # up to 3 attempts per candidate
            ok, result = delete_parcel_once(cand, reason_code, address_type)
            tried.append((cand, attempt, ok))
            if ok:
                return True, {"used": cand, "result": result, "attempt": attempt}
            time.sleep(min(2**attempt, 5))
    return False, {"tried": tried[-5:]}

# ========== Media & OCR ==========
def download_twilio_media(media_url: str) -> Optional[bytes]:
    last = None
    for i in range(1, 4):
        try:
            r = requests.get(media_url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), timeout=15)
            if r.status_code == 200:
                logger.info(f"[media] downloaded {len(r.content)} bytes")
                return r.content
            else:
                logger.warning(f"[media] HTTP {r.status_code}")
        except Exception as e:
            last = e
            logger.warning(f"[media] retry {i} exception: {repr(e)}")
        time.sleep(0.5 * i)
    logger.error(f"[media] failed: {repr(last)}")
    return None

def ocr_image(image_bytes: bytes) -> Optional[str]:
    try:
        logger.info("[ocr] OCR.space")
        url = "https://api.ocr.space/parse/image"
        payload = {
            'apikey': OCR_API_KEY,
            'language': 'eng',
            'isOverlayRequired': False,
            'detectOrientation': True,
            'scale': True,
            'OCREngine': 2
        }
        files = {'file': ('image.jpg', image_bytes, 'image/jpeg')}
        r = requests.post(url, data=payload, files=files, timeout=30)
        if r.status_code != 200:
            logger.error(f"[ocr] HTTP {r.status_code}")
            return None
        result = r.json()
        if result.get('IsErroredOnProcessing'):
            logger.error(f"[ocr] error: {result.get('ErrorMessage')}")
            return None
        pr = result.get('ParsedResults', [])
        if pr:
            text = pr[0].get('ParsedText', '')
            logger.info(f"[ocr] text length: {len(text)}")
            return text
        return None
    except Exception as e:
        logger.error(f"[ocr] exception: {str(e)}", exc_info=True)
        return None

def decode_qrcode_goqr(image_bytes: bytes) -> Optional[str]:
    try:
        url = "https://api.qrserver.com/v1/read-qr-code/"
        files = {'file': ('image.jpg', image_bytes, 'image/jpeg')}
        r = requests.post(url, files=files, timeout=20)
        if r.status_code != 200:
            return None
        result = r.json()
        if result and len(result) > 0:
            symbol = result[0].get('symbol', [])
            if symbol and len(symbol) > 0:
                data = symbol[0].get('data')
                if data:
                    logger.info(f"[qr] sample: {data[:100]}...")
                    ids = smart_extract_parcel_id(data)
                    return ids[0] if ids else None
        return None
    except Exception as e:
        logger.error(f"[qr] exception: {str(e)}")
        return None

def process_image(image_bytes: bytes) -> List[str]:
    # QR first
    ids = []
    qr = decode_qrcode_goqr(image_bytes)
    if qr:
        logger.info(f"[img] QR hit: {qr}")
        ids.append(qr)
        return ids
    # OCR fallback
    txt = ocr_image(image_bytes)
    if txt:
        ext = smart_extract_parcel_id(txt)
        if ext:
            ids.extend(ext)
        else:
            logger.warning("[img] OCR has text but no IDs")
    else:
        logger.warning("[img] OCR failed")
    return ids

# ========== Twilio helpers ==========
def _external_url_for_signature(req):
    proto = req.headers.get('X-Forwarded-Proto', req.scheme)
    host  = req.headers.get('X-Forwarded-Host') or req.headers.get('Host')
    path  = req.full_path if req.query_string else req.path
    return f"{proto}://{host}{path}".rstrip('?')

def verify_twilio_signature(req) -> bool:
    if not VERIFY_TWILIO_SIGNATURE or not TWILIO_AUTH_TOKEN:
        return True
    validator = RequestValidator(TWILIO_AUTH_TOKEN)
    url    = _external_url_for_signature(req)
    params = req.form.to_dict(flat=True)
    sig    = req.headers.get("X-Twilio-Signature", "")
    ok = validator.validate(url, params, sig)
    if not ok:
        logger.warning(f"[sig] failed url={url} sig={sig[:8]}...")
    return ok

def send_followup_text(to_whatsapp: str, body: str):
    """后台通过 Twilio REST 发送文本。优先用 Messaging Service；否则用 FROM 号码。"""
    if not twilio_client:
        logger.warning("[followup] Twilio REST client not configured (SID/TOKEN missing)")
        return
    try:
        kwargs = {"to": to_whatsapp, "body": body}
        if MESSAGING_SERVICE_SID:
            kwargs["messaging_service_sid"] = MESSAGING_SERVICE_SID
        else:
            if not TWILIO_WHATSAPP_FROM:
                logger.error("[followup] Missing TWILIO_WHATSAPP_FROM and no Messaging Service SID; cannot send")
                return
            kwargs["from_"] = TWILIO_WHATSAPP_FROM

        msg = twilio_client.messages.create(**kwargs)
        logger.info(f"[followup] sent ok sid={msg.sid} to={to_whatsapp} via="
                    f"{'svc:'+MESSAGING_SERVICE_SID if MESSAGING_SERVICE_SID else TWILIO_WHATSAPP_FROM}")
    except TwilioRestException as e:
        logger.error(f"[followup] TwilioRestException status={getattr(e,'status',None)} "
                     f"code={getattr(e,'code',None)} msg={getattr(e,'msg',str(e))}")
    except Exception as e:
        logger.exception(f"[followup] Unexpected error: {repr(e)}")

# ========== Health ==========
@app.route("/api/whatsapp_bot", methods=["GET"])
def health():
    has_client = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN)
    sender = TWILIO_WHATSAPP_FROM or "(none)"
    return {
        "status": "ok",
        "service": "WhatsApp Parcel Delete Bot",
        "version": "5.1.1",
        "twilio_client": has_client,
        "sender": sender,
        "messaging_service_sid": MESSAGING_SERVICE_SID or "(none)",
        "verify_signature": VERIFY_TWILIO_SIGNATURE,
        "async_mode": ASYNC_MODE,
        "max_batch_size": MAX_BATCH_SIZE
    }

# ========== Echo route (quick self-test) ==========
@app.post("/wa-echo")
def wa_echo():
    form = request.form.to_dict(flat=True)
    body = (form.get("Body") or "").strip()
    num_media = int(form.get("NumMedia", "0") or "0")
    resp = MessagingResponse()
    if num_media > 0 and body:
        resp.message(f"Echo: received {num_media} image(s) and text: {body[:120]}")
    elif num_media > 0:
        resp.message(f"Echo: received {num_media} image(s).")
    elif body:
        resp.message(f"Echo: received text: {body[:200]}")
    else:
        resp.message("Echo: empty message.")
    return str(resp)

# ========== Main webhook ==========
@app.post("/api/whatsapp_bot")
def webhook():
    if not verify_twilio_signature(request):
        return ("", 403)

    form = request.values
    incoming_msg = (form.get("Body") or "").strip()
    from_number  = form.get("From", "")
    to_number    = form.get("To", "")
    num_media    = int(form.get("NumMedia", 0))
    message_sid  = form.get("MessageSid", "") or form.get("SmsSid", "")

    req_id = str(uuid.uuid4())[:8]
    logger.info(f"[{req_id}] IN sid={message_sid} from={from_number} to={to_number} media={num_media} body='{incoming_msg}'")

    # Idempotency: same MessageSid → ACK only
    if message_sid and RECENT_SIDS.has(message_sid):
        resp = MessagingResponse()
        resp.message("Received (duplicate). Already processed.")
        return str(resp)
    if message_sid:
        RECENT_SIDS.set(message_sid, True)

    # Quick parse for immediate ACK (no network IO)
    quick_ids = smart_extract_parcel_id(incoming_msg) if incoming_msg else []

    resp = MessagingResponse()
    # English ACKs:
    if ASYNC_MODE:
        if num_media > 0 and quick_ids:
            ack = f"Received {len(quick_ids)} text ID(s) and {num_media} image(s). Working on it…"
        elif num_media > 0:
            ack = f"Received {num_media} image(s). Working on it…"
        elif quick_ids:
            ack = f"Received {len(quick_ids)} ID(s). Working on it…"
        else:
            ack = "Message received. I’ll try to extract parcel IDs and get back to you soon."
        resp.message(ack)
        # background
        try:
            POOL.submit(background_process, dict(form), req_id)
        except Exception as e:
            logger.exception(f"[{req_id}] background submit failed: {e}")
        return str(resp)
    else:
        # Fallback: sync pipeline (not recommended for media)
        return sync_pipeline(form, quick_ids, req_id)

def background_process(form_dict: dict, req_id: str):
    try:
        from_number = form_dict.get("From", "")
        num_media   = int(form_dict.get("NumMedia", 0))
        incoming_msg= (form_dict.get("Body") or "").strip()
        message_sid = form_dict.get("MessageSid", "")
        logger.info(f"[{req_id}] BG start sid={message_sid}")

        parcel_ids = set()
        stats = []

        # text first
        if incoming_msg:
            ids = smart_extract_parcel_id(incoming_msg)
            if ids:
                parcel_ids.update(ids)
                stats.append(f"Text: found {len(ids)}")

        # media
        if num_media > 0:
            for i in range(num_media):
                media_url  = form_dict.get(f"MediaUrl{i}", "")
                media_type = form_dict.get(f"MediaContentType{i}", "")
                if not media_url or not media_type.startswith("image/"):
                    stats.append(f"Image {i+1}: not an image")
                    continue
                img = download_twilio_media(media_url)
                if not img:
                    stats.append(f"Image {i+1}: download failed")
                    continue
                before = len(parcel_ids)
                ids = process_image(img)
                for pid in ids: parcel_ids.add(pid)
                new_count = len(parcel_ids) - before
                stats.append(f"Image {i+1}: {'found' if ids else 'no IDs'} ({new_count} new)")

        if not parcel_ids:
            send_followup_text(from_number,
                "No valid parcel IDs were found.\n"
                "Tip: send a clearer screenshot or type the ID like ME176XXXXXXXXXXABC.")
            logger.info(f"[{req_id}] BG no IDs -> notified")
            return

        parcel_list = sorted(parcel_ids)
        if len(parcel_list) > MAX_BATCH_SIZE:
            preview = "\n".join([f"  • {p}" for p in parcel_list[:5]])
            stats_txt = "\n".join(stats) if stats else "(no stats)"
            send_followup_text(from_number,
                f"Too many IDs: {len(parcel_list)} (max {MAX_BATCH_SIZE}).\n\n"
                f"{stats_txt}\n\nFirst 5:\n{preview}\n...\nPlease split into smaller batches.")
            logger.info(f"[{req_id}] BG too many IDs -> notified")
            return

        # delete
        success, failed, used_variant = [], [], {}
        for pid in parcel_list:
            ok, result = delete_parcel_with_variants_retry(pid)
            if ok:
                success.append(pid)
                used = result.get("used", pid)
                if used != pid:
                    used_variant[pid] = used
            else:
                failed.append(pid)

        # report
        summary = f"Total {len(parcel_list)} | Deleted {len(success)} | Failed {len(failed)}"
        lines = [summary, ""]
        if stats:
            lines.append("Recognition summary:")
            lines.extend(stats)
            lines.append("")
        if success:
            lines.append(f"Deleted ({len(success)}):")
            show = success if len(success) <= 20 else success[:20] + [f"... and {len(success)-20} more"]
            for pid in show:
                note = f" (used {used_variant[pid]})" if pid in used_variant else ""
                lines.append(f"  • {pid}{note}")
        if failed:
            lines.append("")
            lines.append(f"Failed ({len(failed)}):")
            showf = failed if len(failed) <= 10 else failed[:10] + [f"... and {len(failed)-10} more"]
            for pid in showf:
                lines.append(f"  • {pid}")

        send_followup_text(from_number, "\n".join(lines))
        logger.info(f"[{req_id}] BG done")
    except Exception as e:
        logger.exception(f"[{req_id}] BG fatal: {e}")
        try:
            send_followup_text(form_dict.get("From",""), f"Background processing error: {repr(e)[:200]}")
        except Exception:
            pass

def sync_pipeline(form, quick_ids, req_id: str):
    try:
        incoming_msg = (form.get("Body") or "").strip()
        from_number  = form.get("From", "")
        num_media    = int(form.get("NumMedia", 0))

        resp = MessagingResponse()
        parcel_ids = set()
        stats = []

        if incoming_msg and quick_ids:
            parcel_ids.update(quick_ids)
            stats.append(f"Text: found {len(quick_ids)}")

        if num_media > 0:
            for i in range(num_media):
                media_url  = form.get(f"MediaUrl{i}", "")
                media_type = form.get(f"MediaContentType{i}", "")
                if not media_url or not media_type.startswith('image/'):
                    stats.append(f"Image {i+1}: not an image")
                    continue
                img = download_twilio_media(media_url)
                if not img:
                    stats.append(f"Image {i+1}: download failed")
                    continue
                before = len(parcel_ids)
                ids = process_image(img)
                for pid in ids: parcel_ids.add(pid)
                new_count = len(parcel_ids) - before
                stats.append(f"Image {i+1}: {'found' if ids else 'no IDs'} ({new_count} new)")

        if not parcel_ids:
            resp.message("No parcel IDs found.\nSend a QR/photo with IDs, or type: ME176XXXXXXXXXXABC")
            return str(resp)

        parcel_list = sorted(parcel_ids)
        if len(parcel_list) > MAX_BATCH_SIZE:
            stats_report = "\n".join(stats)
            preview = '\n'.join([f"  • {p}" for p in parcel_list[:5]])
            resp.message(f"Too many IDs! ({len(parcel_list)})\n\n{stats_report}\n\n"
                         f"Max per batch: {MAX_BATCH_SIZE}\n\nFirst 5:\n{preview}\n...\nPlease split into smaller batches.")
            return str(resp)

        # delete
        success, failed, used_variant = [], [], {}
        for pid in parcel_list:
            ok, result = delete_parcel_with_variants_retry(pid)
            if ok:
                used = result.get("used", pid)
                success.append(pid)
                if used != pid:
                    used_variant[pid] = used
            else:
                failed.append(pid)

        # summary
        summary = f"Deleted {len(success)} | Failed {len(failed)} | Total {len(parcel_list)}"
        resp.message(summary)

        # detail
        lines = []
        if stats:
            lines.append("Recognition summary:")
            lines.append("\n".join(stats))
            lines.append("")
        if success:
            lines.append(f"Deleted ({len(success)}):")
            show = success if len(success) <= 10 else success[:10] + [f"... and {len(success)-10} more"]
            for pid in show:
                note = f" (used {used_variant[pid]})" if pid in used_variant else ""
                lines.append(f"  • {pid}{note}")
        if failed:
            lines.append("")
            lines.append(f"Failed ({len(failed)}):")
            showf = failed if len(failed) <= 5 else failed[:5] + [f"... and {len(failed)-5} more"]
            for pid in showf:
                lines.append(f"  • {pid}")
        resp.message("\n".join(lines) if lines else "No details.")
        return str(resp)

    except Exception as e:
        logger.error(f"[{req_id}] sync fatal: {repr(e)}", exc_info=True)
        resp = MessagingResponse()
        resp.message("System error. Please try again later.")
        return str(resp)

# ========== Manual diag: send a WhatsApp to yourself ==========
@app.get("/diag/twilio")
def diag_twilio():
    """Open in browser: /diag/twilio?to=whatsapp:+61xxxxxxxxx"""
    to = request.args.get("to", "").strip()
    if not to:
        return jsonify(ok=False, error="provide ?to=whatsapp:+61xxxxxxxxx")
    try:
        send_followup_text(to, "Twilio follow-up test: hello from bot.")
        return jsonify(ok=True, to=to,
                       via=MESSAGING_SERVICE_SID or TWILIO_WHATSAPP_FROM or "(none)")
    except Exception as e:
        logger.exception("diag_twilio failed")
        return jsonify(ok=False, error=str(e))
