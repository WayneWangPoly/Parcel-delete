from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import re, json, time, base64, logging, requests, os, itertools
from Crypto.Cipher import AES

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
MAX_BATCH_SIZE = 20  # 单次最多处理20个包裹
MAX_VARIANTS_PER_ID = 8  # 末尾3位0/O纠错的最大尝试数，避免请求爆炸

# 环境变量
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '')
OCR_API_KEY = os.environ.get('OCR_API_KEY', 'K87899142388957')  # 免费 API Key

# 字符映射表（处理西里尔字母等相似字符）
CHAR_REPLACEMENTS = {
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 
    'І': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M', 'О': 'O',
    'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'х': 'x', 'у': 'y'
}

# ========== 工具函数 ==========

def normalize_text(text: str) -> str:
    """标准化文本，替换相似字符"""
    for cyrillic, latin in CHAR_REPLACEMENTS.items():
        text = text.replace(cyrillic, latin)
    return text

def fix_ocr_confusion(text: str) -> str:
    """修复 OCR 常见的字符混淆"""
    text = normalize_text(text)
    return text.upper()

def canonicalize_barcode(raw: str) -> str | None:
    """
    规范化条码：
    结构：ME + 3位“系列” + 10位数字 + 3位字母数字
    - 系列3位：允许 I/l->1，O/o->0
    - 中间10位：强制数字，O->0
    - 末尾3位：允许字母数字（不强行替换，交给变体策略）
    """
    s = fix_ocr_confusion(raw)
    # 宽松捕获一个候选
    m = re.match(r'^ME([0-9OIL]{3})([0-9O]{10})([A-Z0-9O]{3})$', s)
    if not m:
        return None
    series, mid10, last3 = m.groups()

    # 系列位的纠错
    series = series.replace('I', '1').replace('L', '1').replace('O', '0')
    # 中间10位的纠错
    mid10 = mid10.replace('O', '0')

    # 检查系列和中间10位是否全是数字
    if not (series.isdigit() and mid10.isdigit()):
        return None

    return f"ME{series}{mid10}{last3}"

def smart_extract_parcel_id(text: str) -> list[str]:
    """智能提取包裹号，适配动态系列 ME1xx，纠错 I/l/O。"""
    text = fix_ocr_confusion(text)
    text = re.sub(r'\s+', '', text)

    logger.info(f"🔍 处理文本: {text[:120]}...")

    # 宽松匹配：ME + 3位(0/1/…/O/I/L) + 10位(数字或O) + 3位(字母数字或O)
    candidates = re.findall(r'ME[0-9OIL]{3}[0-9O]{10}[A-Z0-9O]{3}', text)
    found = []
    for c in candidates:
        canon = canonicalize_barcode(c)
        if canon and canon not in found:
            found.append(canon)

    if found:
        logger.info(f"✅ 提取到 {len(found)} 个包裹号: {found}")
    else:
        logger.info("❌ 未找到符合格式的包裹号")

    return found

def pkcs7_pad(b: bytes, block_size=16) -> bytes:
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len

def make_data_field(payload_obj: dict) -> str:
    plaintext = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return base64.b64encode(ct).decode('ascii')

def delete_parcel(barcode: str, reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS):
    """调用后端删除包裹（单次尝试）"""
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

        resp = requests.post(url, json=body, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code == 200:
            result = resp.json()
            return result.get('code') == 200, result
        else:
            return False, {"status": resp.status_code, "text": resp.text}
    except Exception as e:
        return False, {"error": str(e)}

def expand_last3_variants(code: str) -> list[str]:
    """
    当末尾3位含 0 / O 时，生成少量替换变体以提高命中率。
    限制最大变体数 MAX_VARIANTS_PER_ID。
    """
    head = code[:-3]
    tail = code[-3:]
    if 'O' not in tail and '0' not in tail:
        return [code]

    positions = []
    for i, ch in enumerate(tail):
        if ch in ('O', '0'):
            positions.append(i)

    # 替换集合：O 与 0 互换尝试
    variants = set()
    max_try = min(MAX_VARIANTS_PER_ID, 1 << len(positions))  # 2^k 上限
    count = 0
    for bits in itertools.product([0,1], repeat=len(positions)):
        tail_list = list(tail)
        for pos_idx, bit in enumerate(bits):
            idx = positions[pos_idx]
            # bit=0: 用 '0'；bit=1: 用 'O'
            tail_list[idx] = '0' if bit == 0 else 'O'
        v = head + ''.join(tail_list)
        variants.add(v)
        count += 1
        if count >= max_try:
            break
    # 确保原始在最前
    ordered = [code] + [v for v in variants if v != code]
    return ordered

def delete_parcel_with_variants(code: str, reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS):
    """
    对末尾3位含 0/O 的条码，按变体顺序尝试删除，任一成功即返回成功。
    """
    for candidate in expand_last3_variants(code):
        ok, result = delete_parcel(candidate, reason_code, address_type)
        if ok:
            return True, {"used": candidate, "result": result}
    # 全部失败，返回最后一次的 result
    return False, {"tried": expand_last3_variants(code)}

def download_twilio_media(media_url: str) -> bytes | None:
    try:
        response = requests.get(
            media_url,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=15
        )
        if response.status_code == 200:
            logger.info(f"✅ 下载成功: {len(response.content)} bytes")
            return response.content
        else:
            logger.error(f"❌ 下载失败: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"下载异常: {str(e)}")
        return None

def ocr_image(image_bytes: bytes) -> str | None:
    try:
        logger.info("📝 OCR 识别中...")
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
        response = requests.post(url, data=payload, files=files, timeout=30)
        if response.status_code != 200:
            logger.error(f"OCR API 失败: {response.status_code}")
            return None
        result = response.json()
        if result.get('IsErroredOnProcessing'):
            logger.error(f"OCR 处理错误: {result.get('ErrorMessage')}")
            return None
        parsed_results = result.get('ParsedResults', [])
        if parsed_results:
            text = parsed_results[0].get('ParsedText', '')
            logger.info(f"✅ OCR 识别文本长度: {len(text)} 字符")
            return text
        return None
    except Exception as e:
        logger.error(f"OCR 异常: {str(e)}", exc_info=True)
        return None

def decode_qrcode_goqr(image_bytes: bytes) -> str | None:
    try:
        url = "https://api.qrserver.com/v1/read-qr-code/"
        files = {'file': ('image.jpg', image_bytes, 'image/jpeg')}
        response = requests.post(url, files=files, timeout=20)
        if response.status_code != 200:
            return None
        result = response.json()
        if result and len(result) > 0:
            symbol = result[0].get('symbol', [])
            if symbol and len(symbol) > 0:
                data = symbol[0].get('data')
                if data:
                    logger.info(f"✅ 二维码内容: {data}")
                    ids = smart_extract_parcel_id(data)
                    return ids[0] if ids else None
        return None
    except Exception as e:
        logger.error(f"二维码识别异常: {str(e)}")
        return None

def process_image(image_bytes: bytes) -> list[str]:
    """处理单张图片：先尝试二维码，再尝试 OCR"""
    parcel_ids = []

    logger.info("🔍 尝试二维码识别...")
    qr_result = decode_qrcode_goqr(image_bytes)
    if qr_result:
        logger.info(f"✅ 二维码识别成功: {qr_result}")
        parcel_ids.append(qr_result)
        return parcel_ids

    logger.info("📝 二维码未找到，尝试 OCR...")
    ocr_text = ocr_image(image_bytes)
    if ocr_text:
        ids = smart_extract_parcel_id(ocr_text)
        if ids:
            logger.info(f"✅ OCR 识别到 {len(ids)} 个包裹号")
            parcel_ids.extend(ids)
        else:
            logger.warning("⚠️ OCR 识别到文字但未找到包裹号")
    else:
        logger.warning("⚠️ OCR 识别失败")

    return parcel_ids

# ========== API 路由 ==========

@app.route("/api/whatsapp_bot", methods=["GET"])
def health():
    has_credentials = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN)
    return {
        "status": "ok",
        "service": "WhatsApp Parcel Delete Bot",
        "version": "4.3.0",
        "twilio_configured": has_credentials,
        "max_batch_size": MAX_BATCH_SIZE,
        "features": [
            "QR Code Recognition",
            "OCR Screenshot Recognition", 
            "Batch Processing",
            "Multi-Image Support",
            "Auto Deduplication",
            "Safety Limits",
            "ME1xx Series Autodetect",
            "Last-3 O/0 Variant Retry",
            "Two-Message Instant Summary"
        ]
    }

@app.route("/api/whatsapp_bot", methods=["POST"])
def webhook():
    try:
        incoming_msg = request.values.get("Body", "").strip()
        from_number = request.values.get("From", "")
        num_media = int(request.values.get("NumMedia", 0))

        logger.info(f"========== 新消息 ==========")
        logger.info(f"发送者: {from_number}")
        logger.info(f"文字消息: '{incoming_msg}'")
        logger.info(f"媒体数量: {num_media}")

        resp = MessagingResponse()
        parcel_ids = set()
        image_stats = []

        # 处理所有图片
        if num_media > 0:
            logger.info(f"📷 开始处理 {num_media} 张图片...")
            for i in range(num_media):
                media_url = request.values.get(f"MediaUrl{i}", "")
                media_type = request.values.get(f"MediaContentType{i}", "")
                if not media_url or not media_type.startswith('image/'):
                    image_stats.append(f"Image {i+1}: ❌ Not an image")
                    logger.warning(f"跳过媒体 {i}: 不是图片类型")
                    continue
                logger.info(f"📸 处理第 {i+1}/{num_media} 张图片...")
                image_bytes = download_twilio_media(media_url)
                if not image_bytes:
                    image_stats.append(f"Image {i+1}: ❌ Download failed")
                    logger.warning(f"❌ 第 {i+1} 张下载失败")
                    continue
                before = len(parcel_ids)
                ids = process_image(image_bytes)
                for pid in ids:
                    parcel_ids.add(pid)
                new_count = len(parcel_ids) - before
                if new_count > 0:
                    image_stats.append(f"Image {i+1}: ✅ Found {len(ids)} ID(s) ({new_count} new)")
                else:
                    image_stats.append(
                        f"Image {i+1}: {'⚠️ Found but all duplicates' if len(ids)>0 else '⚠️ No IDs found'}"
                    )

            if not parcel_ids:
                stats_report = "\n".join(image_stats)
                # 直接一个消息返回（没有IDs就没必要两条）
                m = resp.message()
                m.body(f"❌ No IDs found in {num_media} image(s)!\n\n{stats_report}\n\n"
                       f"Tips:\n• Take clearer photos\n• Ensure text is visible\n• Or type IDs manually (e.g. ME176XXXXXXXXXXABC)")
                return str(resp)

        # 处理文字消息
        if incoming_msg:
            logger.info("📝 处理文字消息...")
            ids = smart_extract_parcel_id(incoming_msg)
            if ids:
                before = len(parcel_ids)
                for pid in ids:
                    parcel_ids.add(pid)
                new_count = len(parcel_ids) - before
                image_stats.append(f"Text: ✅ Found {len(ids)} ID(s) ({new_count} new)")

        if not parcel_ids:
            m = resp.message()
            m.body("❌ No parcel IDs found!\n\nSend:\n• QR code photo\n• Screenshot with IDs\n• Or type: ME176XXXXXXXXXXABC")
            return str(resp)

        parcel_list = sorted(parcel_ids)

        # 数量限制
        if len(parcel_list) > MAX_BATCH_SIZE:
            stats_report = "\n".join(image_stats)
            preview = '\n'.join([f"  • {p}" for p in parcel_list[:5]])
            m = resp.message()
            m.body(f"⚠️ Too many IDs! ({len(parcel_list)})\n\n{stats_report}\n\n"
                   f"Max per batch: {MAX_BATCH_SIZE}\n\nFirst 5:\n{preview}\n...\n\nPlease split into smaller batches.")
            return str(resp)

        # 批量删除（带末尾3位0/O变体重试）
        logger.info(f"🗑️ 开始删除 {len(parcel_list)} 个包裹: {parcel_list}")
        success_list = []
        success_used_variant = {}  # 记录哪个变体生效
        failed_list = []

        for parcel_id in parcel_list:
            ok, result = delete_parcel_with_variants(parcel_id)
            if ok:
                used = result.get("used", parcel_id)
                success_list.append(parcel_id)  # 用原始规范化ID记账
                if used != parcel_id:
                    success_used_variant[parcel_id] = used
                logger.info(f"✅ {parcel_id} 删除成功（实际使用: {used}）")
            else:
                failed_list.append(parcel_id)
                logger.error(f"❌ {parcel_id} 删除失败")

        # —— 先发“抬头概览” —— #
        summary = f"✅ {len(success_list)} deleted | ❌ {len(failed_list)} failed | 📦 {len(parcel_list)} total"
        resp.message(summary)  # 第一条消息：极简概览，抬手即见

        # —— 再发“详细报告” —— #
        report_lines = []

        if image_stats:
            report_lines.append("📊 Recognition Summary:")
            report_lines.append("\n".join(image_stats))
            report_lines.append("")

        if success_list:
            report_lines.append(f"✅ Deleted ({len(success_list)}):")
            show = success_list if len(success_list) <= 10 else success_list[:10] + [f"... and {len(success_list)-10} more"]
            for pid in show:
                if isinstance(pid, str) and pid.startswith("..."):
                    report_lines.append(pid)
                else:
                    # 如果用到变体，标注出来
                    note = f" (used {success_used_variant[pid]})" if pid in success_used_variant else ""
                    report_lines.append(f"  • {pid}{note}")

        if failed_list:
            report_lines.append(f"\n❌ Failed ({len(failed_list)}):")
            showf = failed_list if len(failed_list) <= 5 else failed_list[:5] + [f"... and {len(failed_list)-5} more"]
            for pid in showf:
                report_lines.append(f"  • {pid}")

        detail = "\n".join(report_lines) if report_lines else "No details."
        resp.message(detail)

        return str(resp)

    except Exception as e:
        logger.error(f"💥 系统异常: {str(e)}", exc_info=True)
        resp = MessagingResponse()
        resp.message("❌ System error! Please try again later.")
        return str(resp)
