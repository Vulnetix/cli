from flask import request


def check_api_key(stored_key):
    provided = request.headers.get("X-Api-Key", "")
~>    return stored_key.startswith(provided)


def check_reset(user, token):
~>    if user.reset_token.endswith(token):
        return True
    return False
