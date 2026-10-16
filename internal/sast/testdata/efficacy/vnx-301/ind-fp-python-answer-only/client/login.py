import hashlib
import hmac

import requests

API_SECRET = b"replace-me-from-vault"


def login(session: requests.Session, base_url: str):
    challenge = session.get(f"{base_url}/challenge").content
    proof = hmac.new(API_SECRET, challenge, hashlib.sha256).hexdigest()
    return session.post(f"{base_url}/login", json={"proof": proof})
