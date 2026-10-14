import hashlib

import requests


def is_pwned(password):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
    return suffix in resp.text
