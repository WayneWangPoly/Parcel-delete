from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import re, json, time, base64, logging, requests
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

# 🔧 相似字符映射表（西里尔字母 → 拉丁字母）
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
    # 🔧 先标准化字符（西里尔 → 拉丁）
    text = normalize_text(text)
    logger.info(f"标准化后: '{text}'")
    
    # 移除所有空格、换行符
    text = re.sub(r'\s+', '', text.upper())
    logger.info(f"清理后的文本: '{text}', 长度: {len(text)}")
    
    pattern = r'ME175\d{10}[A-Z0-9]{3}'
    match = re.search(pattern, text)
    
    if match:
        logger.info(f"✅ 匹配成功: {match.group(0)}")
        return match.group(0)
    else:
        logger.info(f"❌ 匹配失败，文本内容: {repr(text)}")
        # 显示每个字符的 Unicode 编码帮助调试
        char_codes = [f"{c}(U+{ord(c):04X})" for c in text[:10]]
        logger.info(f"前10个字符编码: {' '.join(char_codes)}")
        return None

@app.route("/api/whatsapp_bot", methods=["GET"])
def health():
    return {
        "status": "ok",
        "service": "WhatsApp Parcel Delete Bot",
        "version": "1.0.2"
    }

@app.route("/api/whatsapp_bot", methods=["POST"])
def webhook():
    try:
        incoming_msg = request.values.get("Body", "").strip()
        from_number = request.values.get("From", "")
        
        logger.info(f"========== 新消息 ==========")
        logger.info(f"发送者: {from_number}")
        logger.info(f"原始消息: '{incoming_msg}'")
        logger.info(f"消息长度: {len(incoming_msg)}")
        
        resp = MessagingResponse()
        msg = resp.message()
        
        parcel_id = extract_parcel_id(incoming_msg)
        
        if not parcel_id:
            msg.body(f"❌ Invalid format!\n\nPlease check your parcel ID.\nExpected format:\nME1759420465462KBA\n\n💡 Tip: Type manually instead of copy-paste")
            logger.info("❌ 格式验证失败")
            return str(resp)
        
        logger.info(f"🔄 准备删除包裹: {parcel_id}")
        success, result = delete_parcel(parcel_id)
        
        if success:
            logger.info(f"✅ 删除成功: {parcel_id}")
            msg.body(f"✅ Success!\n{parcel_id} has been deleted.")
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
