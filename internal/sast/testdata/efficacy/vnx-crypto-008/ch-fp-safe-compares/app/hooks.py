import hmac


def ok(sig, expected):
    if sig is None or expected == "":
        return False
    return hmac.compare_digest(sig, expected)
