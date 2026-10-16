import jwt


def peek(token):
    # Reported by the signature-verification rule, not the none-algorithm rule.
    return jwt.decode(token, options={"verify_signature": False})
