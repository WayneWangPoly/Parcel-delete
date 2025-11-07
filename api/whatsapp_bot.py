from flask import Flask, request, jsonify
from twilio.twiml.messaging_response import MessagingResponse
from twilio.rest import Client as TwilioClient
import re, json, time, base64, logging, requests, os, itertools, io, hmac, hashlib
from Crypto.Cipher import AES
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("wa-bot")

# ========== 配置 ==========
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

# 环境变量
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN  = os.environ.get('TWILIO_AUTH_TOKEN', '')
TWILIO_WHATSAPP_FROM = os.environ.get('TWILIO_WHATSAPP_FROM', '')  # 例如 "whatsapp:+14155238886"
VERIFY_TWILIO_SIGNATURE = os.environ.get('VERIFY_TWILIO_SIGNATURE', '0') == '1'
ASYNC_MODE = os.environ.get('ASYNC_MODE', '1') == '1'

OCR_API_KEY = os.environ.get('OCR_API_KEY', 'K87899142388957')

twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN) else None
pool = ThreadPoolExecutor(max_workers=8)

# 字符映射表
CHAR_REPLACEMENTS = {
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H',
    'І': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M', 'О': 'O',
    'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'х': 'x', 'у': 'y'
}

# ========== 工具函数 ==========
def normalize_text(text: str) -> str:
    for cyrillic, latin in CHAR_REPLACEMENTS.items():
        text = text.replace(cyrillic, latin)
    return text

def fix_ocr_confusion(text: str) -> str:
    text = normalize_text(text)
    return text.upper()

def canonicalize_barcode(raw: str) -> str | None:
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

def smart_extract_parcel_id(text: str) -> list[str]:
    text = fix_ocr_confusion(text)
    text = re.sub(r'\s+', '', text)
    logger.info(f"🔍 文本抽取窗口: {text[:160]}...")
    candidates = re.findall(r'ME[0-9OIL]{3}[0-9O]{10}[A-Z0-9O]{3}', text)
    found = []
    for c in candidates:
        canon = canonicalize_barcode(c)
        if canon and canon not in found:
            found.append(canon)
    if found:
        logger.info(f"✅ 提取 {len(found)} 个ID: {found}")
    else:
        logger.info("❌ 未找到符合格式的ID")
    return found

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

def delete_parcel(barcode: str, reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS):
    try:
        payload = {
            "bar_code": barcode.strip().upper(),
            "reason_code": reason_code,
            "address_type": address_type,
            "myme_timestamp": int(time.time() * 1000)
        }
        data_field = make_data_field(payload)
        body = {"data": data_field}
        url = URL_BASE + ENDPOINT
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

def expand_last3_variants(code: str) -> list[str]:
    head = code[:-3]; tail = code[-3:]
    if 'O' not in tail and '0' not in tail:
        return [code]
    positions = [i for i,ch in enumerate(tail) if ch in ('O','0')]
    variants = {code}
    limit = min(MAX_VARIANTS_PER_ID, 1 << len(positions))
    cnt = 0
    for bits in itertools.product([0,1], repeat=len(positions)):
        tl = list(tail)
        for idx, bit in enumerate(bits):
            pos = positions[idx]
            tl[pos] = '0' if bit == 0 else 'O'
        variants.add(head + ''.join(tl))
        cnt += 1
        if cnt >= limit: break
    return [v for v in variants]

def delete_parcel_with_variants(code: str, reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS):
    tried = []
    for candidate in expand_last3_variants(code):
        tried.append(candidate)
        ok, result = delete_parcel(candidate, reason_code, address_type)
        if ok:
            return True, {"used": candidate, "result": result}
    return False, {"tried": tried}

def download_twilio_media(media_url: str) -> bytes | None:
    # 带认证 + 重试
    last = None
    for i in range(1, 4):
        try:
            r = requests.get(media_url, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN), timeout=15)
            if r.status_code == 200:
                logger.info(f"✅ 媒体下载成功 {len(r.content)} bytes")
                return r.content
            else:
                logger.warning(f"❌ 媒体下载失败 HTTP {r.status_code}")
        except Exception as e:
            last = e
            logger.warning(f"媒体下载异常重试 {i}: {repr(e)}")
        time.sleep(0.5 * i)
    logger.error(f"媒体下载最终失败: {repr(last)}")
    return None

def ocr_image(image_bytes: bytes) -> str | None:
    try:
        logger.info("📝 OCR 调用中...")
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
            logger.error(f"OCR HTTP {r.status_code}")
            return None
        result = r.json()
        if result.get('IsErroredOnProcessing'):
            logger.error(f"OCR 处理错误: {result.get('ErrorMessage')}")
            return None
        pr = result.get('ParsedResults', [])
        if pr:
            text = pr[0].get('ParsedText', '')
            logger.info(f"✅ OCR 文本长度: {len(text)}")
            return text
        return None
    except Exception as e:
        logger.error(f"OCR 异常: {str(e)}", exc_info=True)
        return None

def decode_qrcode_goqr(image_bytes: bytes) -> str | None:
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
                    logger.info(f"✅ QR内容: {data[:100]}...")
                    ids = smart_extract_parcel_id(data)
                    return ids[0] if ids else None
        return None
    except Exception as e:
        logger.error(f"二维码识别异常: {str(e)}")
        return None

def process_image(image_bytes: bytes) -> list[str]:
    ids = []
    logger.info("🔍 尝试二维码识别...")
    qr = decode_qrcode_goqr(image_bytes)
    if qr:
        logger.info(f"✅ QR命中: {qr}")
        return [qr]
    logger.info("📝 二维码未命中，转 OCR...")
    txt = ocr_image(image_bytes)
    if txt:
        res = smart_extract_parcel_id(txt)
        if res:
            logger.info(f"✅ OCR 提取 {len(res)} 个ID")
            ids.extend(res)
        else:
            logger.warning("⚠️ OCR 有文本但无ID")
    else:
        logger.warning("⚠️ OCR 失败")
    return ids

def verify_twilio_signature(req) -> bool:
    if not VERIFY_TWILIO_SIGNATURE or not TWILIO_AUTH_TOKEN:
        return True
    sig = req.headers.get("X-Twilio-Signature", "")
    # 构造基串：完整URL + 按参数名排序连接的值
    url = request.url
    params = req.form.to_dict(flat=True)
    s = url + "".join(v for _, v in sorted(params.items()))
    digest = base64.b64encode(hmac.new(TWILIO_AUTH_TOKEN.encode(), s.encode(), hashlib.sha1).digest()).decode()
    ok = hmac.compare_digest(sig, digest)
    if not ok:
        logger.warning("Twilio Signature 校验失败")
    return ok

def send_followup_text(to_whatsapp: str, body: str):
    if not twilio_client or not TWILIO_WHATSAPP_FROM:
        logger.warning("Twilio REST 未配置，无法发送跟进消息")
        return
    try:
        twilio_client.messages.create(
            from_=TWILIO_WHATSAPP_FROM,
            to=to_whatsapp,
            body=body
        )
        logger.info("📤 已通过 Twilio REST 发送跟进消息")
    except Exception as e:
        logger.error(f"发送跟进消息失败: {repr(e)}")

# ========== 健康检查 ==========
@app.route("/api/whatsapp_bot", methods=["GET"])
def health():
    has_credentials = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN)
    return {
        "status": "ok",
        "service": "WhatsApp Parcel Delete Bot",
        "version": "5.0.0",
        "twilio_configured": has_credentials,
        "async_mode": ASYNC_MODE,
        "max_batch_size": MAX_BATCH_SIZE,
        "features": [
            "Ack-first async processing",
            "QR + OCR recognition",
            "Variant retry for last-3 O/0",
            "Batch & limits",
            "Dedup-ready hooks",
            "Twilio signature (optional)"
        ]
    }

# ========== 主 Webhook ==========
@app.route("/api/whatsapp_bot", methods=["POST"])
def webhook():
    if not verify_twilio_signature(request):
        return ("", 403)

    # Twilio 使用 form-urlencoded；MessageSid 很关键
    form = request.values
    incoming_msg = (form.get("Body") or "").strip()
    from_number = form.get("From", "")
    num_media = int(form.get("NumMedia", 0))
    message_sid = form.get("MessageSid", "")
    logger.info(f"========= INBOUND =========")
    logger.info(f"Sid={message_sid} From={from_number} Media={num_media} Body='{incoming_msg[:180]}'")

    # 先做轻量解析（不做网络IO），马上回执
    quick_ids = smart_extract_parcel_id(incoming_msg) if incoming_msg else []
    resp = MessagingResponse()

    if ASYNC_MODE:
        # —— 异步模式：立即给用户一个明确的“已收到” —— #
        if num_media > 0 and quick_ids:
            ack = f"✅ 收到文本ID {len(quick_ids)} 个，另有 {num_media} 张图片，正在处理…"
        elif num_media > 0:
            ack = f"📸 收到 {num_media} 张图片，正在识别…"
        elif quick_ids:
            ack = f"✅ 收到 {len(quick_ids)} 个ID，正在处理…"
        else:
            ack = "👋 已收到你的消息，正在识别编号…（如有紧急，请直接发送形如 ME176XXXXXXXXXXABC 的文本）"
        resp.message(ack)
        # 提交后台处理
        try:
            pool.submit(background_process, dict(form))
        except Exception as e:
            logger.exception("后台任务提交失败")
        return str(resp)
    else:
        # —— 同步模式：沿用你原本的“识别 + 删除 + 两条回复”的逻辑 —— #
        return sync_pipeline(form, quick_ids)

def background_process(form_dict: dict):
    """后台完整处理：下载媒体 -> QR/OCR -> 合并文本ID -> 限流 -> 变体删除 -> 通过 Twilio REST 回报告"""
    try:
        from_number = form_dict.get("From", "")
        num_media = int(form_dict.get("NumMedia", 0))
        incoming_msg = (form_dict.get("Body") or "").strip()
        message_sid = form_dict.get("MessageSid", "")
        logger.info(f"[BG] Start Sid={message_sid}")

        parcel_ids = set()
        image_stats = []

        # 文字先抽
        if incoming_msg:
            ids = smart_extract_parcel_id(incoming_msg)
            if ids:
                parcel_ids.update(ids)
                image_stats.append(f"Text: ✅ Found {len(ids)}")

        # 媒体识别
        if num_media > 0:
            logger.info(f"[BG] 处理 {num_media} 张图片")
            for i in range(num_media):
                media_url = form_dict.get(f"MediaUrl{i}", "")
                media_type = form_dict.get(f"MediaContentType{i}", "")
                if not media_url or not media_type.startswith("image/"):
                    image_stats.append(f"Image {i+1}: ❌ Not image")
                    continue
                img = download_twilio_media(media_url)
                if not img:
                    image_stats.append(f"Image {i+1}: ❌ Download failed")
                    continue
                before = len(parcel_ids)
                ids = process_image(img)
                for pid in ids: parcel_ids.add(pid)
                new_count = len(parcel_ids) - before
                image_stats.append(f"Image {i+1}: {'✅' if new_count>0 else '⚠️'} Found {len(ids)} ({new_count} new)")

        if not parcel_ids:
            body = "❌ 未识别到可用的包裹号。\n建议：发送更清晰的截图或直接输入形如 ME176XXXXXXXXXXABC 的文本编号。"
            send_followup_text(from_number, body)
            logger.info(f"[BG] Sid={message_sid} 无ID，已通知用户")
            return

        parcel_list = sorted(parcel_ids)
        if len(parcel_list) > MAX_BATCH_SIZE:
            preview = "\n".join([f"  • {p}" for p in parcel_list[:5]])
            stats = "\n".join(image_stats) if image_stats else ""
            body = (f"⚠️ IDs 过多：{len(parcel_list)}（上限 {MAX_BATCH_SIZE}）。\n\n"
                    f"{stats}\n\n前5个：\n{preview}\n...\n请分批发送。")
            send_followup_text(from_number, body)
            logger.info(f"[BG] Sid={message_sid} 超量，已提示分批")
            return

        # 删除
        logger.info(f"[BG] 删除 {len(parcel_list)} 个：{parcel_list}")
        success, failed, used_variant = [], [], {}
        for pid in parcel_list:
            ok, result = delete_parcel_with_variants(pid)
            if ok:
                success.append(pid)
                used = result.get("used", pid)
                if used != pid:
                    used_variant[pid] = used
            else:
                failed.append(pid)

        # 汇总
        summary = f"✅ {len(success)} deleted | ❌ {len(failed)} failed | 📦 {len(parcel_list)} total"
        lines = [summary, ""]
        if image_stats:
            lines.append("📊 Recognition Summary:")
            lines.append("\n".join(image_stats))
            lines.append("")

        if success:
            lines.append(f"✅ Deleted ({len(success)}):")
            show = success if len(success) <= 12 else success[:12] + [f"... and {len(success)-12} more"]
            for pid in show:
                note = f" (used {used_variant[pid]})" if pid in used_variant else ""
                lines.append(f"  • {pid}{note}")

        if failed:
            lines.append("")
            lines.append(f"❌ Failed ({len(failed)}):")
            showf = failed if len(failed) <= 8 else failed[:8] + [f"... and {len(failed)-8} more"]
            for pid in showf:
                lines.append(f"  • {pid}")

        send_followup_text(from_number, "\n".join(lines))
        logger.info(f"[BG] 完成 Sid={message_sid}")
    except Exception as e:
        logger.exception(f"[BG] 致命异常：{repr(e)}")

def sync_pipeline(form, quick_ids):
    """保留你的同步两条消息风格；当 ASYNC_MODE=0 时使用"""
    try:
        incoming_msg = (form.get("Body") or "").strip()
        from_number = form.get("From", "")
        num_media = int(form.get("NumMedia", 0))

        resp = MessagingResponse()
        parcel_ids = set()
        image_stats = []

        if incoming_msg and quick_ids:
            parcel_ids.update(quick_ids)
            image_stats.append(f"Text: ✅ Found {len(quick_ids)}")

        if num_media > 0:
            for i in range(num_media):
                media_url = form.get(f"MediaUrl{i}", "")
                media_type = form.get(f"MediaContentType{i}", "")
                if not media_url or not media_type.startswith('image/'):
                    image_stats.append(f"Image {i+1}: ❌ Not an image")
                    continue
                img = download_twilio_media(media_url)
                if not img:
                    image_stats.append(f"Image {i+1}: ❌ Download failed")
                    continue
                before = len(parcel_ids)
                ids = process_image(img)
                for pid in ids: parcel_ids.add(pid)
                new_count = len(parcel_ids) - before
                image_stats.append(f"Image {i+1}: {'✅' if new_count>0 else '⚠️'} Found {len(ids)} ({new_count} new)")

        if not parcel_ids:
            m = resp.message()
            m.body("❌ No parcel IDs found!\n\nSend:\n• QR code photo\n• Screenshot with IDs\n• Or type: ME176XXXXXXXXXXABC")
            return str(resp)

        parcel_list = sorted(parcel_ids)

        if len(parcel_list) > MAX_BATCH_SIZE:
            stats_report = "\n".join(image_stats)
            preview = '\n'.join([f"  • {p}" for p in parcel_list[:5]])
            m = resp.message()
            m.body(f"⚠️ Too many IDs! ({len(parcel_list)})\n\n{stats_report}\n\n"
                   f"Max per batch: {MAX_BATCH_SIZE}\n\nFirst 5:\n{preview}\n...\n\nPlease split into smaller batches.")
            return str(resp)

        # 删除
        success_list, failed_list, success_used_variant = [], [], {}
        for parcel_id in parcel_list:
            ok, result = delete_parcel_with_variants(parcel_id)
            if ok:
                used = result.get("used", parcel_id)
                success_list.append(parcel_id)
                if used != parcel_id:
                    success_used_variant[parcel_id] = used
            else:
                failed_list.append(parcel_id)

        # 第一条：概览
        summary = f"✅ {len(success_list)} deleted | ❌ {len(failed_list)} failed | 📦 {len(parcel_list)} total"
        resp.message(summary)

        # 第二条：明细
        report_lines = []
        if image_stats:
            report_lines.append("📊 Recognition Summary:")
            report_lines.append("\n".join(image_stats))
            report_lines.append("")
        if success_list:
            report_lines.append(f"✅ Deleted ({len(success_list)}):")
            show = success_list if len(success_list) <= 10 else success_list[:10] + [f"... and {len(success_list)-10} more"]
            for pid in show:
                note = f" (used {success_used_variant[pid]})" if pid in success_used_variant else ""
                report_lines.append(f"  • {pid}{note}")
        if failed_list:
            report_lines.append("")
            report_lines.append(f"❌ Failed ({len(failed_list)}):")
            showf = failed_list if len(failed_list) <= 5 else failed_list[:5] + [f"... and {len(failed_list)-5} more"]
            for pid in showf:
                report_lines.append(f"  • {pid}")
        resp.message("\n".join(report_lines) if report_lines else "No details.")

        return str(resp)
    except Exception as e:
        logger.error(f"同步管线异常: {repr(e)}", exc_info=True)
        resp = MessagingResponse()
        resp.message("❌ System error! Please try again later.")
        return str(resp)
