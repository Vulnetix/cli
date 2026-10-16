import os
import secrets
import uuid


def new_api_key() -> str:
    api_key = secrets.token_urlsafe()
    return api_key


def new_session_token() -> str:
    session_token = secrets.token_hex(32)
    return session_token


def new_salt() -> bytes:
    salt = os.urandom(16)
    return salt


def new_invite() -> str:
    invite_token = uuid.uuid4().hex
    return invite_token
