"""
WhatsApp包裹删除机器人 - Vercel Serverless 版本
"""

from twilio.twiml.messaging_response import MessagingResponse
import re
import json
import time
import base64
import logging
from Crypto.Cipher import AES
import requests

# ========== 日志配置 ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== 加密配置 ==========
KEY = b"1236987410000111"
IV  = b"1236987410000111"

URL_BASE = "https://microexpress.com.au"
ENDPOINT = "/smydriver/delete-sudo-parcel"

HEADERS = {
    "Content-Type": "application/json;UTF-8",
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile Html5Plus/1.0 uni-app",
    "Accept-Language": "en-AU,en;q=0.9"
}

DEFAULT_REASON = "NOREASON"
DEFAULT_ADDRESS = "house"
TIMEOUT = 15

# ========== 加密函数 ==========
def pkcs7_pad(b: bytes, block_size=16) -> bytes:
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len

def make_data_field(payload_obj: dict) -> str:
    """加密 payload"""
    plaintext = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return base64.b64encode(ct).decode('ascii')

# ========== 删除包裹函数 ==========
def delete_parcel(barcode: str, reason_code: str = DEFAULT_REASON,
                  address_type: str = DEFAULT_ADDRESS) -> tuple:
    """删除包裹，返回 (success: bool, result: dict)"""
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

        logger.info(f"尝试删除包裹: {barcode}")
        resp = requests.post(url, json=body, headers=HEADERS, timeout=TIMEOUT)
        status = resp.status_code
        logger.info(f"响应状态: {status}, 内容: {resp.text}")

        if status == 200:
            result = resp.json()
            if result.get('code') == 200:
                return True, result
            else:
                return False, result
        else:
            return False, {"status": status, "text": resp.text}

    except Exception as e:
        logger.error(f"删除失败: {str(e)}")
        return False, {"error": str(e)}

# ========== 提取包裹号 ==========
def extract_parcel_id(text: str) -> str:
    """从文本中提取 ME 开头的包裹号"""
    text = text.upper()
    pattern = r'ME175\d{10}[A-Z0-9]{3}'
    match = re.search(pattern, text)
    return match.group(0) if match else None

# ========== Vercel Serverless Handler ==========
def handler(request=None):
    try:
        method = getattr(request, "method", "GET") if request else "GET"

        if method == "GET":
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "status": "ok",
                    "service": "WhatsApp Parcel Delete Bot",
                    "version": "1.0.0"
                })
            }

        return {
            "statusCode": 405,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Method not allowed"})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }

    # Webhook 消息处理
    if method == "POST":
        try:
            body = request.get_json() or {}
            incoming_msg = body.get("Body", "")
            from_number = body.get("From", "")

            logger.info(f"收到消息 from={from_number}: {incoming_msg}")

            resp = MessagingResponse()
            msg = resp.message()

            # 提取包裹号
            parcel_id = extract_parcel_id(incoming_msg)
            if not parcel_id:
                msg.body("❌ Invalid format! Send parcel ID like ME1759420465462KBA")
                return {
                    "statusCode": 200,
                    "headers": {"Content-Type": "application/xml"},
                    "body": str(resp)
                }

            # 删除包裹
            success, result = delete_parcel(parcel_id)
            if success:
                msg.body(f"✅ Success!\n{parcel_id} deleted.")
                logger.info(f"✅ 成功删除: {parcel_id}")
            else:
                error_msg = result.get('msg', 'Unknown error')
                msg.body(f"❌ Failed!\n{error_msg}\nTry again!")
                logger.error(f"❌ 删除失败: {parcel_id}, 错误: {error_msg}")

            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/xml"},
                "body": str(resp)
            }

        except Exception as e:
            logger.error(f"处理消息异常: {str(e)}")
            resp = MessagingResponse()
            resp.message("❌ System error. Please try again later.")
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/xml"},
                "body": str(resp)
            }

    # 其他方法不支持
    return {
        "statusCode": 405,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": "Method not allowed"})
    }
