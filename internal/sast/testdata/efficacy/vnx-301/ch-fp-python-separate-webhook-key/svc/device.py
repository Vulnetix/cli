import hashlib
import hmac
import os

DEVICE_KEY = os.environ["DEVICE_KEY"].encode()
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()


def answer_challenge(challenge):
    return hmac.new(DEVICE_KEY, challenge, hashlib.sha256).hexdigest()


def webhook_ok(body, signature):
    mac = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, signature)
