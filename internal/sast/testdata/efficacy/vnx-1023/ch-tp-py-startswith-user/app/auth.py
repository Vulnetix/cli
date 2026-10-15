from flask import request, abort

API_KEY = load_key()


def require_key():
    supplied = request.headers.get("X-Api-Key", "")
~>    if not API_KEY.startswith(supplied):
        abort(401)


def check_reset(stored_token, given):
~>    return stored_token.endswith(given)
