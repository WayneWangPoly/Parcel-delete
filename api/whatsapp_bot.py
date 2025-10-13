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

TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '')

CHAR_REPLACEMENTS = {
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 
    'І': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M', 'О': 'O',
    'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'х': 'x', 'у': 'y'
}

def normalize_text(text: str) -> str:
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
    text = normalize_text(text)
    text = re.sub(r'\s+', '', text.upper())
    pattern = r'ME175\d{10}[A-Z0-9]{3}'
    match = re.search(pattern, text)
    if match:
        return match.group(0)
    return None

def download_twilio_media(media_url: str) -> bytes:
    try:
        response = requests.get(
            media_url,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=15
        )
        if response.status_code == 200:
            return response.content
        return None
    except Exception as e:
        logger.error(f"下载异常: {str(e)}")
        return None

def decode_qrcode_goqr(image_bytes: bytes) -> str:
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
                    return extract_parcel_id(data)
        return None
    except Exception as e:
        logger.error(f"识别异常: {str(e)}")
        return None

@app.route("/api/whatsapp_bot", methods=["GET"])
def health():
    has_credentials = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN)
    return {
        "status": "ok",
        "service": "WhatsApp Parcel Delete Bot (Batch)",
        "version": "3.0.0",
        "twilio_configured": has_credentials
    }

@app.route("/api/whatsapp_bot", methods=["POST"])
def webhook():
    try:
        incoming_msg = request.values.get("Body", "").strip()
        from_number = request.values.get("From", "")
        num_media = int(request.values.get("NumMedia", 0))
        
        logger.info(f"========== 新消息 ==========")
        logger.info(f"发送者: {from_number}")
        logger.info(f"文字: '{incoming_msg}'")
        logger.info(f"媒体数量: {num_media}")
        
        resp = MessagingResponse()
        msg = resp.message()
        
        parcel_ids = set()  # 使用 set 去重
        
        # 🔄 批量处理所有图片
        if num_media > 0:
            logger.info(f"📷 处理 {num_media} 张图片...")
            
            for i in range(num_media):
                media_url = request.values.get(f"MediaUrl{i}", "")
                media_type = request.values.get(f"MediaContentType{i}", "")
                
                if not media_url or not media_type.startswith('image/'):
                    logger.warning(f"跳过媒体 {i}: 不是图片")
                    continue
                
                logger.info(f"📸 处理第 {i+1}/{num_media} 张图片...")
                
                # 下载图片
                image_bytes = download_twilio_media(media_url)
                if not image_bytes:
                    logger.warning(f"❌ 第 {i+1} 张下载失败")
                    continue
                
                # 识别二维码
                parcel_id = decode_qrcode_goqr(image_bytes)
                if parcel_id:
                    logger.info(f"✅ 第 {i+1} 张识别到: {parcel_id}")
                    parcel_ids.add(parcel_id)
                else:
                    logger.warning(f"⚠️ 第 {i+1} 张未识别到二维码")
            
            # 如果没有识别到任何二维码
            if not parcel_ids:
                msg.body(f"❌ No QR codes found in {num_media} image(s)!\n\nTry:\n• Clearer photos\n• Better lighting\n• Or type IDs")
                return str(resp)
        
        # 📝 处理文字消息（可能包含多个包裹号）
        if incoming_msg:
            logger.info("📝 处理文字消息...")
            # 查找所有符合格式的包裹号
            pattern = r'ME175\d{10}[A-Z0-9]{3}'
            matches = re.findall(pattern, normalize_text(incoming_msg).upper())
            for match in matches:
                logger.info(f"✅ 文字识别到: {match}")
                parcel_ids.add(match)
        
        # 验证是否有包裹号
        if not parcel_ids:
            msg.body("❌ No parcel IDs found!\n\nSend:\n• QR code photo(s)\n• Or ID(s): ME1759420465462KBA")
            return str(resp)
        
        # 🗑️ 批量删除
        parcel_list = sorted(list(parcel_ids))
        logger.info(f"🗑️ 准备删除 {len(parcel_list)} 个包裹: {parcel_list}")
        
        success_list = []
        failed_list = []
        
        for parcel_id in parcel_list:
            success, result = delete_parcel(parcel_id)
            if success:
                logger.info(f"✅ {parcel_id} 删除成功")
                success_list.append(parcel_id)
            else:
                error = result.get('msg', result.get('error', 'Unknown'))
                logger.error(f"❌ {parcel_id} 删除失败: {error}")
                failed_list.append(f"{parcel_id}: {error}")
        
        # 📊 生成报告
        report_lines = []
        
        if success_list:
            report_lines.append(f"✅ Deleted ({len(success_list)}):")
            for pid in success_list:
                report_lines.append(f"  • {pid}")
        
        if failed_list:
            report_lines.append(f"\n❌ Failed ({len(failed_list)}):")
            for item in failed_list:
                report_lines.append(f"  • {item}")
        
        if not success_list and not failed_list:
            report_lines.append("⚠️ No parcels processed")
        
        msg.body("\n".join(report_lines))
        return str(resp)
        
    except Exception as e:
        logger.error(f"💥 系统异常: {str(e)}", exc_info=True)
        resp = MessagingResponse()
        resp.message("❌ System error!")
        return str(resp)
