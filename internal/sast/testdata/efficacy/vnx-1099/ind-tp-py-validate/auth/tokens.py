import hmac


def validate_token(token, secret):
    return hmac.compare_digest(token, sign(secret))


~>def validateToken(token, secret):
    return token == sign(secret)
