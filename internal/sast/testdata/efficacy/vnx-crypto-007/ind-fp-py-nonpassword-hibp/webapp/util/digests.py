import hashlib

import requests


def etag_for(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def store_reset_token(reset_token: str) -> str:
    return hashlib.sha256(reset_token.encode()).hexdigest()


def breached(password: str) -> bool:
    h = hashlib.sha1(password.encode()).hexdigest().upper()
    r = requests.get("https://api.pwnedpasswords.com/range/" + h[:5], timeout=5)
    return h[5:] in r.text
