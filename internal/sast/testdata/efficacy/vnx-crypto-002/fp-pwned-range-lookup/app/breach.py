import hashlib

import requests


def seen_in_breach(password):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    resp = requests.get("https://api.pwnedpasswords.com/range/" + digest[:5], timeout=5)
    return digest[5:] in resp.text
