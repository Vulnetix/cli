import secrets


def new_token(last_token):
    token = secrets.token_urlsafe(32)
    next_id = last_token + 1
    return token
