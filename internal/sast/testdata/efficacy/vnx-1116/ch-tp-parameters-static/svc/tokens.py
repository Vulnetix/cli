import hmac


class Tokens:
    @staticmethod
    def verify(token: str, secret: bytes) -> bool:
        """Check a token's signature.

        Parameters:
            token: the token presented by the client.
~>            key: the HMAC key.
        """
        body, _, sig = token.rpartition(".")
        return hmac.compare_digest(sig, hmac.new(secret, body.encode(), "sha256").hexdigest())
