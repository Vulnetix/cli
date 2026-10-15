import hmac


def sign_body(secret: bytes, body: bytes) -> str:
~>    mac = hmac.HMAC(secret, body)
    return mac.hexdigest()


def sign_webhook(secret, payload):
~>    digest = hmac.new(
        key=secret,
        msg=payload,
    ).hexdigest()
    return digest
