from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import re, json, time, base64, logging, requests, os
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
    text = normalize_text(text).upper()
    
    # 替换容易混淆的字符
    replacements = {
        'О': '0',  # 西里尔字母 O
        'o': '0',  # 小写 o
        'ο': '0',  # 希腊小写 omicron
        'Ο': '0',  # 希腊大写 Omicron
    }
    
    for old, new in replacements.items():
        text = text.replace(old, new)
    
    return text

def smart_extract_parcel_id(text: str) -> list:
    """智能提取包裹号，处理 OCR 错误"""
    text = fix_ocr_confusion(text)
    text = re.sub(r'\s+', '', text)
    
    logger.info(f"🔍 处理文本: {text[:100]}...")
    
    found_ids = []
    
    # 模式1：标准匹配 ME175 + 10位数字 + 3位字母数字
    pattern1 = r'ME176\d{10}[A-Z0-9]{3}'
    matches1 = re.findall(pattern1, text)
    found_ids.extend(matches1)
    
    # 模式2：宽松匹配（允许中间10位有O）
    pattern2 = r'ME176[0-9O]{10}[A-Z0-9]{3}'
    matches2 = re.findall(pattern2, text)
    for match in matches2:
        # 将中间10位的O替换为0
        fixed = match[:5] + match[5:15].replace('O', '0') + match[15:]
        if fixed not in found_ids:
            found_ids.append(fixed)
    
    # 模式3：处理 ME 后的 I/l/1 混淆
    pattern3 = r'ME[I1l]76[0-9O]{10}[A-Z0-9]{3}'
    matches3 = re.findall(pattern3, text)
    for match in matches3:
        # ME 后必须是 1
        fixed = 'ME1' + match[3:]
        fixed = fixed[:5] + fixed[5:15].replace('O', '0') + fixed[15:]
        if fixed not in found_ids and re.match(r'ME175\d{10}[A-Z0-9]{3}', fixed):
            found_ids.append(fixed)
    
    if found_ids:
        logger.info(f"✅ 提取到 {len(found_ids)} 个包裹号: {found_ids}")
    else:
        logger.info(f"❌ 未找到符合格式的包裹号")
    
    return found_ids

def pkcs7_pad(b: bytes, block_size=16) -> bytes:
    """PKCS7 填充"""
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len

def make_data_field(payload_obj: dict) -> str:
    """生成加密的 data 字段"""
    plaintext = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return base64.b64encode(ct).decode('ascii')

def delete_parcel(barcode: str, reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS):
    """删除包裹"""
    try:
        barcode = barcode.strip().upper()
        payload = {
            "bar_code": barcode,
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

def download_twilio_media(media_url: str) -> bytes:
    """从 Twilio 下载媒体文件（需要认证）"""
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

def ocr_image(image_bytes: bytes) -> str:
    """使用 OCR.space API 识别图片文字"""
    try:
        logger.info(f"📝 OCR 识别中...")
        
        url = "https://api.ocr.space/parse/image"
        payload = {
            'apikey': OCR_API_KEY,
            'language': 'eng',
            'isOverlayRequired': False,
            'detectOrientation': True,
            'scale': True,
            'OCREngine': 2  # 引擎2对数字识别更好
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

def decode_qrcode_goqr(image_bytes: bytes) -> str:
    """使用 GoQR.me API 识别二维码"""
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

def process_image(image_bytes: bytes) -> list:
    """处理单张图片：先尝试二维码，再尝试 OCR"""
    parcel_ids = []
    
    # 1️⃣ 先尝试二维码识别（快速且准确）
    logger.info("🔍 尝试二维码识别...")
    qr_result = decode_qrcode_goqr(image_bytes)
    if qr_result:
        logger.info(f"✅ 二维码识别成功: {qr_result}")
        parcel_ids.append(qr_result)
        return parcel_ids
    
    # 2️⃣ 二维码失败，尝试 OCR（适合截图）
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
    """健康检查接口"""
    has_credentials = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN)
    return {
        "status": "ok",
        "service": "WhatsApp Parcel Delete Bot",
        "version": "4.2.0",
        "twilio_configured": has_credentials,
        "max_batch_size": MAX_BATCH_SIZE,
        "features": [
            "QR Code Recognition",
            "OCR Screenshot Recognition", 
            "Batch Processing",
            "Multi-Image Support",
            "Auto Deduplication",
            "Safety Limits"
        ]
    }

@app.route("/api/whatsapp_bot", methods=["POST"])
def webhook():
    """WhatsApp 消息处理主函数"""
    try:
        incoming_msg = request.values.get("Body", "").strip()
        from_number = request.values.get("From", "")
        num_media = int(request.values.get("NumMedia", 0))
        
        logger.info(f"========== 新消息 ==========")
        logger.info(f"发送者: {from_number}")
        logger.info(f"文字消息: '{incoming_msg}'")
        logger.info(f"媒体数量: {num_media}")
        
        resp = MessagingResponse()
        msg = resp.message()
        
        parcel_ids = set()  # 使用 set 自动去重
        image_stats = []  # 记录每张图片的识别统计
        
        # 🖼️ 处理所有图片
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
                
                # 下载图片
                image_bytes = download_twilio_media(media_url)
                if not image_bytes:
                    image_stats.append(f"Image {i+1}: ❌ Download failed")
                    logger.warning(f"❌ 第 {i+1} 张下载失败")
                    continue
                
                # 记录处理前的数量
                before_count = len(parcel_ids)
                
                # 识别图片（二维码或 OCR）
                ids = process_image(image_bytes)
                for pid in ids:
                    parcel_ids.add(pid)
                
                # 统计这张图片新增的数量
                new_count = len(parcel_ids) - before_count
                
                if new_count > 0:
                    image_stats.append(f"Image {i+1}: ✅ Found {len(ids)} ID(s) ({new_count} new)")
                    logger.info(f"✅ 第 {i+1} 张识别到 {len(ids)} 个，新增 {new_count} 个")
                else:
                    if len(ids) > 0:
                        image_stats.append(f"Image {i+1}: ⚠️ Found {len(ids)} ID(s) (all duplicates)")
                    else:
                        image_stats.append(f"Image {i+1}: ⚠️ No IDs found")
                    logger.warning(f"⚠️ 第 {i+1} 张未找到新的包裹号")
            
            # 如果所有图片都没找到包裹号
            if not parcel_ids:
                stats_report = "\n".join(image_stats)
                msg.body(f"❌ No IDs found in {num_media} image(s)!\n\n"
                         f"{stats_report}\n\n"
                         f"Tips:\n• Take clearer photos\n• Ensure text is visible\n• Or type IDs manually")
                return str(resp)
        
        # 📝 处理文字消息
        if incoming_msg:
            logger.info("📝 处理文字消息...")
            ids = smart_extract_parcel_id(incoming_msg)
            if ids:
                before_count = len(parcel_ids)
                for pid in ids:
                    parcel_ids.add(pid)
                new_count = len(parcel_ids) - before_count
                image_stats.append(f"Text: ✅ Found {len(ids)} ID(s) ({new_count} new)")
                logger.info(f"✅ 文字消息识别到 {len(ids)} 个，新增 {new_count} 个")
        
        # 验证是否有包裹号
        if not parcel_ids:
            msg.body("❌ No parcel IDs found!\n\n"
                     "Send:\n• QR code photo\n• Screenshot with IDs\n• Or type: ME1759420465462KBA")
            return str(resp)
        
        parcel_list = sorted(list(parcel_ids))
        
        # 🛡️ 安全检查：数量限制
        if len(parcel_list) > MAX_BATCH_SIZE:
            logger.warning(f"⚠️ 数量超限: {len(parcel_list)} > {MAX_BATCH_SIZE}")
            stats_report = "\n".join(image_stats)
            preview = '\n'.join([f"  • {p}" for p in parcel_list[:5]])
            msg.body(f"⚠️ Too many IDs! ({len(parcel_list)})\n\n"
                     f"{stats_report}\n\n"
                     f"Max per batch: {MAX_BATCH_SIZE}\n\n"
                     f"First 5:\n{preview}\n...\n\n"
                     f"Please split into smaller batches.")
            return str(resp)
        
        # 🗑️ 批量删除包裹
        logger.info(f"🗑️ 开始删除 {len(parcel_list)} 个包裹: {parcel_list}")
        
        success_list = []
        failed_list = []
        
        for parcel_id in parcel_list:
            success, result = delete_parcel(parcel_id)
            if success:
                logger.info(f"✅ {parcel_id} 删除成功")
                success_list.append(parcel_id)
            else:
                error = result.get('msg', result.get('error', 'Unknown error'))
                logger.error(f"❌ {parcel_id} 删除失败: {error}")
                failed_list.append(f"{parcel_id}: {error}")
        
        # 📊 生成详细报告
        report = []
        
        # 显示识别统计
        if image_stats:
            report.append("📊 Recognition Summary:")
            report.append("\n".join(image_stats))
            report.append("")  # 空行分隔
        
        # 显示成功列表
        if success_list:
            report.append(f"✅ Deleted ({len(success_list)}):")
            # 如果数量太多，只显示前10个
            if len(success_list) > 10:
                for pid in success_list[:10]:
                    report.append(f"  • {pid}")
                report.append(f"  ... and {len(success_list) - 10} more")
            else:
                for pid in success_list:
                    report.append(f"  • {pid}")
        
        # 显示失败列表
        if failed_list:
            report.append(f"\n❌ Failed ({len(failed_list)}):")
            # 最多显示前5个失败
            for item in failed_list[:5]:
                report.append(f"  • {item}")
            if len(failed_list) > 5:
                report.append(f"  ... and {len(failed_list) - 5} more")
        
        msg.body("\n".join(report))
        return str(resp)
        
    except Exception as e:
        logger.error(f"💥 系统异常: {str(e)}", exc_info=True)
        resp = MessagingResponse()
        resp.message("❌ System error! Please try again later.")
        return str(resp)

# Vercel 自动识别 app 变量作为入口
