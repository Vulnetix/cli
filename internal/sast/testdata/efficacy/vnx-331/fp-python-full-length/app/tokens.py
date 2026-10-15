import os
import secrets
import uuid


def new_reset_token():
    return secrets.token_urlsafe(32)


def api_key():
    return secrets.token_hex()


def session_id():
    return secrets.token_bytes(16)


SECRET_KEY = os.urandom(32)
token = str(uuid.uuid4())
