#!/usr/bin/env python3
"""
delete_parcels_batch.py - 修复版

修复：IV是固定的，不需要作为前缀加到密文中
"""

import json
import time
import base64
import argparse
import logging
from Crypto.Cipher import AES
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from tqdm import tqdm
from time import sleep
from typing import Tuple, Dict

# ---------- 配置 ----------
KEY = b"1236987410000111"   # 16 bytes - 固定
IV  = b"1236987410000111"   # 16 bytes - 固定

URL_BASE = "https://microexpress.com.au"
ENDPOINT = "/smydriver/delete-sudo-parcel"

HEADERS = {
    "Content-Type": "application/json;UTF-8",
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile Html5Plus/1.0 uni-app",
    "Accept-Language": "en-AU,en;q=0.9"
}

DEFAULT_CONCURRENCY = 2
DEFAULT_RATE_PER_SEC = 2.0
MAX_RETRIES = 3
TIMEOUT = 15

DEFAULT_REASON = "NOREASON"
DEFAULT_ADDRESS = "house"

# ---------- 日志 ----------
logging.basicConfig(
    filename='delete_parcels.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

# ---------- 辅助字典 ----------
VALID_REASON = {
    "1": "RETN-ADDEF",
    "2": "RETN-NSG",
    "3": "NOREASON",
    "RETN-ADDEF": "RETN-ADDEF",
    "RETN-NSG": "RETN-NSG",
    "NOREASON": "NOREASON"
}

VALID_ADDRESS = {
    "1": "house",
    "2": "apartment",
    "3": "shop",
    "4": "school",
    "5": "factory",
    "6": "office",
    "7": "hotel",
    "house": "house",
    "apartment": "apartment",
    "shop": "shop",
    "school": "school",
    "factory": "factory",
    "office": "office",
    "hotel": "hotel"
}

# ---------- 加解密工具 ----------
def pkcs7_pad(b: bytes, block_size=16) -> bytes:
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len

def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if pad < 1 or pad > 16:
        return b
    return b[:-pad]

def make_data_field(payload_obj: dict, key=KEY, iv=IV) -> str:
    """
    构造和客户端一致的 data 字段
    
    重要：IV是固定的，不作为前缀加到密文中！
    """
    plaintext = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    # 关键修复：只返回密文，不加IV前缀
    return base64.b64encode(ct).decode('ascii')

def decrypt_data_field(data_b64: str, key=KEY, iv=IV) -> str:
    """解密data字段"""
    raw = base64.b64decode(data_b64)
    # IV是固定的，不在数据中
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(raw)
    pt = pkcs7_unpad(pt)
    try:
        return pt.decode('utf-8')
    except Exception:
        return repr(pt)

# ---------- 请求函数 ----------
def post_delete(barcode: str, reason_code: str = DEFAULT_REASON, address_type: str = DEFAULT_ADDRESS,
                timestamp_ms: int = None, debug: bool = False) -> Tuple[bool, Dict]:
    """
    构造明文 payload 并发请求
    """
    barcode = barcode.strip().upper()

    payload = {
        "bar_code": barcode,
        "reason_code": reason_code,
        "address_type": address_type
    }

    if timestamp_ms is None:
        payload["myme_timestamp"] = int(time.time() * 1000)
    else:
        payload["myme_timestamp"] = int(timestamp_ms)

    data_field = make_data_field(payload)
    body = {"data": data_field}

    if debug:
        return True, {
            "payload": body,
            "plaintext": payload,
            "encrypted_data": data_field
        }

    url = URL_BASE + ENDPOINT
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # 移除 verify=False，启用SSL验证（更安全）
            resp = requests.post(url, json=body, headers=HEADERS, timeout=TIMEOUT)
            status = resp.status_code
            text = resp.text
            logging.info("barcode=%s attempt=%d status=%s resp=%s", barcode, attempt, status, text)
            try:
                j = resp.json()
                # 检查返回码
                if j.get("code") == 200:
                    return True, j
                else:
                    logging.warning("barcode=%s returned non-200 code: %s", barcode, j)
                    return False, j
            except Exception:
                return (status == 200), {"status": status, "text": text}
        except Exception as exc:
            logging.warning("barcode=%s attempt=%d exception=%s", barcode, attempt, exc)
            if attempt < MAX_RETRIES:
                sleep(1.5 * attempt)
            else:
                return False, {"error": str(exc)}

# ---------- 批量控制 ----------
def run_batch(barcodes, concurrency=DEFAULT_CONCURRENCY, rate_per_sec=DEFAULT_RATE_PER_SEC,
              reason_code=DEFAULT_REASON, address_type=DEFAULT_ADDRESS, debug=False, timestamp_ms=None):
    results = {}
    interval = 1.0 / max(1, rate_per_sec)
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {}
        for bc in barcodes:
            future = ex.submit(post_delete, bc, reason_code, address_type, timestamp_ms, debug)
            futures[future] = bc
            time.sleep(interval)
        for future in tqdm(as_completed(futures), total=len(futures), desc="Deleting"):
            bc = futures[future]
            try:
                ok, resp = future.result()
                results[bc] = (ok, resp)
            except Exception as exc:
                results[bc] = (False, {"error": str(exc)})
    return results

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="Batch delete parcels (FIXED VERSION)")
    ap.add_argument("--single", help="single barcode (e.g. ME175...)", default=None)
    ap.add_argument("--file", help="file with one barcode per line", default=None)
    ap.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    ap.add_argument("--rate", type=float, default=DEFAULT_RATE_PER_SEC)
    ap.add_argument("--reason", help="reason code or index (default: 3/NOREASON)", default="3")
    ap.add_argument("--address", help="address type or index (default: 1/house)", default="1")
    ap.add_argument("--debug", action="store_true", help="debug mode: only generate payload")
    ap.add_argument("--ts", type=int, default=None, help="fix timestamp (ms)")
    args = ap.parse_args()

    def normalize_reason(r):
        r = str(r).strip()
        return VALID_REASON.get(r, r)

    def normalize_address(a):
        a = str(a).strip()
        return VALID_ADDRESS.get(a, a)

    reason_code = normalize_reason(args.reason)
    address_type = normalize_address(args.address)

    if args.single:
        bc = args.single.strip().upper()
        print(f"正在删除包裹: {bc}")
        print(f"Reason: {reason_code}, Address: {address_type}")
        
        ok, resp = post_delete(bc, reason_code, address_type, timestamp_ms=args.ts, debug=args.debug)
        
        if args.debug:
            print("\n【调试模式 - 不发送请求】")
            print(f"明文Payload:")
            print(json.dumps(resp['plaintext'], indent=2, ensure_ascii=False))
            print(f"\n加密后的data:")
            print(resp['encrypted_data'])
            print(f"\n完整请求体:")
            print(json.dumps(resp['payload'], indent=2, ensure_ascii=False))
        else:
            print("\n【结果】")
            print(f"成功: {ok}")
            print(json.dumps(resp, ensure_ascii=False, indent=2))
            
            if ok:
                print("\n✅ 删除成功！")
            else:
                print("\n❌ 删除失败！")
                
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            barcodes = [line.strip().upper() for line in f if line.strip()]
        if not barcodes:
            print("文件中没有找到包裹号")
            return
        
        print(f"准备批量删除 {len(barcodes)} 个包裹...")
        results = run_batch(barcodes, concurrency=args.concurrency, rate_per_sec=args.rate,
                            reason_code=reason_code, address_type=address_type, 
                            debug=args.debug, timestamp_ms=args.ts)
        
        # 统计
        success_count = sum(1 for ok, _ in results.values() if ok)
        
        # 保存结果
        out_file = 'delete_results.json'
        with open(out_file, 'w', encoding='utf-8') as wf:
            json.dump(results, wf, ensure_ascii=False, indent=2)
        
        print(f"\n批量删除完成！")
        print(f"成功: {success_count}/{len(barcodes)}")
        print(f"详细结果已保存到: {out_file}")
    else:
        ap.print_help()

if __name__ == "__main__":
    main()
