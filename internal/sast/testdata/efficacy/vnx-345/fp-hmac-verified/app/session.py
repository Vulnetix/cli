import base64
import hashlib
import hmac
import pickle

from flask import request

SECRET = load_key()


def load_prefs():
    raw = base64.b64decode(request.cookies["prefs"])
    sig, body = raw[:32], raw[32:]
    if not hmac.compare_digest(sig, hmac.new(SECRET, body, hashlib.sha256).digest()):
        abort(400)
    return pickle.loads(body)
