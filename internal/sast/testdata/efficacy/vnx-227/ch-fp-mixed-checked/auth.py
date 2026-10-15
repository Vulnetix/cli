import hmac


class Account:
    def check_password(self, raw):
        return verify_hash(self.hash, raw)


def valid(sig, expected):
    return hmac.compare_digest(sig, expected)


def webhook(sig, expected):
    if not hmac.compare_digest(sig, expected):
        raise PermissionError("bad signature")
