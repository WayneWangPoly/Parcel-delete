from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import re, json, time, base64, logging, requests, os
from Crypto.Cipher import AES

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# 🔑 从环境变量获取 Twilio 凭证
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '')

# 相似字符映射表
CHAR_REPLACEMENTS = {
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 
    'І': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M', 'О': 'O',
    'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'х': 'x', 'у': 'y'
}

def normalize_text(text: str) -> str:
    """标准化文本，替换相似字符"""
    for cyrillic, latin in CHAR_REPLACEMENTS.items():
        text = text.replace(cyrillic, latin)
    return text

def pkcs7_pad(b: bytes, block_size=16) -> bytes:
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len

def make_data_field(payload_obj: dict) -> str:
    plaintext = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return base64.b64encode(ct).decode('ascii')

def delete_parcel(barcode: str, reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS):
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

def extract_parcel_id(text: str) -> str:
    """从文本中提取包裹号"""
    text = normalize_text(text)
    text = re.sub(r'\s+', '', text.upper())
    logger.info(f"清理后的文本: '{text}'")
    
    pattern = r'ME175\d{10}[A-Z0-9]{3}'
    match = re.search(pattern, text)
    
    if match:
        logger.info(f"✅ 匹配成功: {match.group(0)}")
        return match.group(0)
    else:
        logger.info(f"❌ 文本匹配失败")
        return None

def download_twilio_media(media_url: str) -> bytes:
    """从 Twilio 下载媒体文件（需要认证）"""
    try:
        logger.info(f"📥 下载 Twilio 媒体: {media_url}")
        
        # 使用 Twilio 凭证进行 Basic Auth
        response = requests.get(
            media_url,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=15
        )
        
        if response.status_code == 200:
            logger.info(f"✅ 媒体下载成功，大小: {len(response.content)} bytes")
            return response.content
        else:
            logger.error(f"❌ 媒体下载失败: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"下载媒体异常: {str(e)}")
        return None

def decode_qrcode_from_image(image_bytes: bytes) -> str:
    """使用在线 API 解析二维码（上传图片数据）"""
    try:
        logger.info(f"📷 使用 API 解析二维码，图片大小: {len(image_bytes)} bytes")
        
        # 使用 api.qrserver.com 的上传接口
        api_url = "https://api.qrserver.com/v1/read-qr-code/"
        
        # 上传图片文件
        files = {'file': ('qrcode.jpg', image_bytes, 'image/jpeg')}
        response = requests.post(api_url, files=files, timeout=15)
        
        if response.status_code != 200:
            logger.error(f"API 请求失败: {response.status_code}")
            return None
        
        result = response.json()
        logger.info(f"API 返回: {result}")
        
        # 解析返回结果
        if result and len(result) > 0:
            symbol_data = result[0].get('symbol', [])
            if symbol_data and len(symbol_data) > 0:
                qr_data = symbol_data[0].get('data', '')
                
                if qr_data:
                    logger.info(f"🔍 二维码内容: {qr_data}")
                    # 从二维码内容中提取包裹号
                    parcel_id = extract_parcel_id(qr_data)
                    return parcel_id
                else:
                    error = symbol_data[0].get('error', 'unknown')
                    logger.warning(f"二维码解析错误: {error}")
        
        logger.warning("API 未能识别二维码")
        return None
        
    except Exception as e:
        logger.error(f"二维码解析异常: {str(e)}", exc_info=True)
        return None

@app.route("/api/whatsapp_bot", methods=["GET"])
def health():
    return {
        "status": "ok",
        "service": "WhatsApp Parcel Delete Bot (Text + QR)",
        "version": "2.2.0"
    }

@app.route("/api/whatsapp_bot", methods=["POST"])
def webhook():
    try:
        incoming_msg = request.values.get("Body", "").strip()
        from_number = request.values.get("From", "")
        
        # 检查是否有图片
        num_media = int(request.values.get("NumMedia", 0))
        media_url = request.values.get("MediaUrl0", "")
        media_type = request.values.get("MediaContentType0", "")
        
        logger.info(f"========== 新消息 ==========")
        logger.info(f"发送者: {from_number}")
        logger.info(f"文字消息: '{incoming_msg}'")
        logger.info(f"媒体数量: {num_media}")
        if num_media > 0:
            logger.info(f"媒体类型: {media_type}")
            logger.info(f"媒体URL: {media_url}")
        
        resp = MessagingResponse()
        msg = resp.message()
        
        parcel_id = None
        
        # 1️⃣ 优先处理图片（二维码）
        if num_media > 0 and media_url:
            if media_type.startswith('image/'):
                logger.info("📷 检测到图片消息，尝试识别二维码...")
                
                # 先下载 Twilio 媒体
                image_bytes = download_twilio_media(media_url)
                
                if image_bytes:
                    # 然后识别二维码
                    parcel_id = decode_qrcode_from_image(image_bytes)
                    
                    if parcel_id:
                        logger.info(f"✅ 二维码识别成功: {parcel_id}")
                    else:
                        logger.warning("❌ 未能从图片识别出包裹号")
                        msg.body("❌ QR code not recognized!\n\nPlease:\n• Send clearer image\n• Ensure QR code is visible\n• Or type parcel ID directly")
                        return str(resp)
                else:
                    msg.body("❌ Failed to download image!\n\nPlease try again.")
                    return str(resp)
            else:
                msg.body(f"❌ Unsupported media type: {media_type}\n\nPlease send image or text.")
                return str(resp)
        
        # 2️⃣ 如果没有图片，处理文字消息
        if not parcel_id and incoming_msg:
            logger.info("📝 处理文字消息...")
            parcel_id = extract_parcel_id(incoming_msg)
        
        # 3️⃣ 验证是否获取到包裹号
        if not parcel_id:
            msg.body("❌ Invalid format!\n\nPlease send:\n• QR code image, or\n• Parcel ID like: ME1759420465462KBA")
            return str(resp)
        
        # 4️⃣ 执行删除操作
        logger.info(f"🔄 准备删除包裹: {parcel_id}")
        success, result = delete_parcel(parcel_id)
        
        if success:
            logger.info(f"✅ 删除成功: {parcel_id}")
            msg.body(f"✅ Success!\n📦 {parcel_id}\nhas been deleted.")
        else:
            error_msg = result.get('msg', result.get('error', 'Unknown error'))
            logger.error(f"❌ 删除失败: {error_msg}")
            msg.body(f"❌ Failed!\n{error_msg}\n\nPlease try again!")
        
        return str(resp)
        
    except Exception as e:
        logger.error(f"💥 系统异常: {str(e)}", exc_info=True)
        resp = MessagingResponse()
        resp.message("❌ System error. Please try again later.")
        return str(resp)
