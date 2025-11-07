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
TWILIO_ACCOUNT_SID      = os.environ.get('TWILIO_ACCOUNT_SID', '').strip()
TWILIO_AUTH_TOKEN       = os.environ.get('TWILIO_AUTH_TOKEN', '').strip()
TWILIO_WHATSAPP_FROM    = os.environ.get('TWILIO_WHATSAPP_FROM', '').strip()  # e.g. "whatsapp:+14155238886"
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
