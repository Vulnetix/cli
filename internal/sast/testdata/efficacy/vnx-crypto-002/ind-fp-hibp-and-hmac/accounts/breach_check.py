import hashlib
import hmac

import requests


def is_pwned(password: str) -> bool:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
    return any(line.split(":")[0] == suffix for line in resp.text.splitlines())


def oauth1_signature(key: bytes, base_string: bytes) -> bytes:
    return hmac.new(key, base_string, hashlib.sha1).digest()


def legacy_mac(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, digestmod=hashlib.sha1).hexdigest()
