# -*- coding: utf-8 -*-
import os, re, json, time, base64, logging, requests, itertools, uuid
from typing import Optional, List
from flask import Flask, request, jsonify, Response
from twilio.twiml.messaging_response import MessagingResponse

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("wa-bot-safe")

# -------- 基本配置 --------
KEY = os.environ.get("AES_KEY", "1236987410000111").encode()
IV  = os.environ.get("AES_IV",  "1236987410000111").encode()
URL_BASE = os.environ.get("API_BASE", "https://microexpress.com.au")
ENDPOINT = os.environ.get("API_DELETE", "/smydriver/delete-sudo-parcel")
HEADERS = {
    "Content-Type": "application/json;UTF-8",
    "User-Agent": "Mozilla/5.0",
    "Accept-Language": "en-AU,en;q=0.9"
}
DEFAULT_REASON   = "NOREASON"
DEFAULT_ADDRESS  = "house"
TIMEOUT          = 12
MAX_BATCH_SIZE   = 20
MAX_VARIANTS     = 8

TWILIO_ACCOUNT_SID   = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN    = os.environ.get("TWILIO_AUTH_TOKEN",  "").strip()
TWILIO_WHATSAPP_FROM = os.environ.get("TWILIO_WHATSAPP_FROM", "").strip()  # whatsapp:+15558432115
VERIFY_TWILIO_SIGNATURE = os.environ.get("VERIFY_TWILIO_SIGNATURE", "0") == "1"
OCR_API_KEY = os.environ.get("OCR_API_KEY", "K87899142388957").strip()

# -------- 文本抽取 --------
CHAR_REPL = {'А':'A','В':'B','С':'C','Е':'E','Н':'H','І':'I','Ј':'J','К':'K','М':'M','О':'O','Р':'P','Ѕ':'S','Т':'T','Х':'X','У':'Y',
             'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y'}

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

# -------- 安全加密：延迟导入 AES，缺库时也能给出提示 --------
def pkcs7_pad(b: bytes, bs=16) -> bytes:
    pad = bs - (len(b) % bs)
    return b + bytes([pad])*pad

def make_data_field(payload: dict) -> str:
    try:
        from Crypto.Cipher import AES  # 延迟导入
    except Exception as e:
        raise RuntimeError("PyCryptodome not installed: pip install pycryptodome") from e
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pkcs7_pad(json.dumps(payload, separators=(',',':')).encode()))
    return base64.b64encode(ct).decode()

# -------- HTTP 后端 --------
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
            r = requests.post(url, json=body, headers=HEADERS, timeout=TIMEOUT)
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

# -------- 媒体/OCR（超时收敛; 延迟失败也会回一条消息） --------
def dl_media(url: str) -> Optional[bytes]:
    try:
        r = requests.get(url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), timeout=10)
        if r.status_code == 200:
            return r.content
    except Exception:
        pass
    return None

def ocr_space(img: bytes) -> Optional[str]:
    try:
        r = requests.post(
            "https://api.ocr.space/parse/image",
            data={'apikey': OCR_API_KEY, 'language':'eng', 'isOverlayRequired': False, 'OCREngine':2},
            files={'file': ('image.jpg', img, 'image/jpeg')},
            timeout=10
        )
        if r.status_code!=200: return None
        js = r.json()
        if js.get("IsErroredOnProcessing"): return None
        pr = js.get("ParsedResults", [])
        if pr:
            return pr[0].get("ParsedText","")
        return None
    except Exception:
        return None

def process_image(img: bytes) -> List[str]:
    text = ocr_space(img)
    return extract_ids(text or "") if text else []

# -------- 健康检查 --------
@app.get("/api/whatsapp_bot")
def health():
    return jsonify({
        "status":"ok",
        "version":"safe-1.0",
        "twilio_from": TWILIO_WHATSAPP_FROM or "(none)",
        "verify_sig": VERIFY_TWILIO_SIGNATURE,
        "base": URL_BASE,
        "endpoint": ENDPOINT
    })

# -------- Webhook：单条消息 = ACK + 明细 --------
@app.post("/api/whatsapp_bot")
def webhook():
    # 不做签名校验的原因：很多人先要跑通路径。等稳定后再开。
    form = request.values
    body = (form.get("Body") or "").strip()
    nmed = int(form.get("NumMedia", 0))
    sid  = form.get("MessageSid","") or form.get("SmsSid","")
    rid  = str(uuid.uuid4())[:8]
    log.info(f"[{rid}] IN sid={sid} media={nmed} body='{body[:80]}'")

    # 先识别（文本）
    ids = extract_ids(body) if body else []

    # 再识别（图片）
    stats = []
    if nmed>0:
        for i in range(nmed):
            mu  = form.get(f"MediaUrl{i}", "")
            mt  = form.get(f"MediaContentType{i}", "")
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
                if g not in ids: ids.append(g)
            stats.append(f"Image {i+1}: {'found' if got else 'no IDs'} (+{len(ids)-before})")

    # 组 ACK 头
    if nmed>0 and body:
        ack = f"✅ Received text and 🖼️ {nmed} image(s). Working on it…"
    elif nmed>0:
        ack = f"🖼️ Received {nmed} image(s). Working on it…"
    elif body:
        ack = f"✅ Received your message. Working on it…"
    else:
        ack = "👋 Message received. Working on it…"

    # 没识别到
    if not ids:
        reply = ack + "\n\n" + "❌ No parcel IDs found.\n💡 Send a clear screenshot or type: ME176XXXXXXXXXXABC"
        tw = MessagingResponse(); tw.message(reply)
        return Response(str(tw), mimetype="application/xml")

    # 数量限制
    if len(ids) > MAX_BATCH_SIZE:
        preview = "\n".join([f"  • {x}" for x in ids[:5]])
        stattxt = "\n".join(stats) if stats else ""
        reply = (f"{ack}\n\n⚠️ Too many IDs: {len(ids)} (max {MAX_BATCH_SIZE}).\n"
                 f"{stattxt}\n\nFirst 5:\n{preview}\n...\nPlease split into smaller batches.")
        tw = MessagingResponse(); tw.message(reply)
        return Response(str(tw), mimetype="application/xml")

    # 删除
    succ, fail, used = [], [], {}
    for pid in ids:
        ok, res = delete_with_variants(pid)
        if ok:
            succ.append(pid)
            if res.get("used") and res["used"] != pid:
                used[pid] = res["used"]
        else:
            fail.append(pid)

    lines = [ack, ""]
    lines.append(f"📦 Total {len(ids)} | ✅ Deleted {len(succ)} | ❌ Failed {len(fail)}")
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

    tw = MessagingResponse(); tw.message("\n".join(lines))
    return Response(str(tw), mimetype="application/xml")
