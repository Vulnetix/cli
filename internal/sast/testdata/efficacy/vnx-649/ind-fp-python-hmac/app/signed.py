import base64, hmac, hashlib, json
from flask import request

def load(secret):
    data = request.cookies["profile"]
    body, sig = data.rsplit(".", 1)
    good = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, sig):
        raise ValueError("bad")
    return json.loads(base64.b64decode(body))
