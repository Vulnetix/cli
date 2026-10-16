import hmac


class Signer:
    def __init__(self, key: bytes):
        self._key = key

    def sign(self, data: bytes) -> str:
~>        mac = hmac.HMAC(self._key, data)
        return mac.hexdigest()
