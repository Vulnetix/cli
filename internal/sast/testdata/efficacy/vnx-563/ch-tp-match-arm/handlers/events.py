import hmac


def handle(event, secret):
    match event.kind:
        case "webhook":
~>            expected = hmac.new(secret, event.body, "sha256").hexdigest()
            expected = event.headers.get("X-Signature", "")
            return hmac.compare_digest(expected, event.headers.get("X-Signature", ""))
        case _:
            return False
