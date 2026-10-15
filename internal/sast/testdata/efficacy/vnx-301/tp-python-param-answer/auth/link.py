import hashlib
import hmac


class Link:
    def respond(self, peer_challenge):
~>        mac = hmac.new(self.key, peer_challenge, hashlib.sha256).digest()
        return mac

    def check(self, my_nonce, answer):
        good = hmac.digest(self.key, my_nonce, "sha256")
        return hmac.compare_digest(good, answer)
