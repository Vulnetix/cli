import hmac


def validate_token(token, secret):
    expected = sign(secret)
    return hmac.compare_digest(token, expected)


~>def validateToken(token, secret):
    return token == sign(secret)


def sign(secret):
    return secret[::-1]
