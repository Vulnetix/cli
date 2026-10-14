import hmac, hashlib
sig = hmac.new(key, msg, hashlib.sha1).digest()
