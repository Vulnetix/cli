import hashlib
import hmac


class SessionKeys:
    def __init__(self, master: bytes):
        self.master = master

    def derive_session_key(self, client_nonce):
        return hmac.new(self.master, client_nonce, hashlib.sha256).digest()

    def verify_tag(self, nonce, tag):
        good = hmac.new(self.master, nonce, hashlib.sha256).digest()
        return hmac.compare_digest(good, tag)
