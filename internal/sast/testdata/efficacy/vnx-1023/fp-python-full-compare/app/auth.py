import hmac

from flask import request

TOKEN_PREFIX = "vnx_"


def check(stored_key):
    provided = request.headers.get("Authorization", "")
    if not provided.startswith("Bearer "):
        return False
    token = provided[len("Bearer "):]
    if not token.startswith(TOKEN_PREFIX):
        return False
    return hmac.compare_digest(stored_key, token)


def short(token):
    # return stored.startswith(token) was the old check
    label = "use token.startswith(provided) never"
    return token[:8] + "..."
