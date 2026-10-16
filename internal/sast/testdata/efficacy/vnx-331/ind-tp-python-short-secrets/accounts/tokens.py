import os
import secrets
import uuid


def new_api_key() -> str:
~>    api_key = secrets.token_hex(4)
    return api_key


def new_salt() -> bytes:
~>    salt = os.urandom(4)
    return salt


def new_session() -> str:
~>    session_id = str(uuid.uuid1())
    return session_id


def new_invite() -> str:
~>    invite_token = uuid.uuid4().hex[:8]
    return invite_token
