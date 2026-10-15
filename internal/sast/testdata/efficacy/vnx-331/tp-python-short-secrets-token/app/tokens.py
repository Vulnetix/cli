import secrets


def new_reset_token():
~>    return {"reset_token": secrets.token_urlsafe(6)}


def api_key():
~>    api_key = secrets.token_hex(4)
    return api_key


class Session:
    def __init__(self):
~>        self.session_id = secrets.token_bytes( 8 )
