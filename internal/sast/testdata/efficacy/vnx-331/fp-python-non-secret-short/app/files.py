import os
import secrets
import uuid


def upload_name(ext):
    return f"upload-{secrets.token_hex(4)}.{ext}"


def request_id():
    return uuid.uuid1().hex


def nonce12():
    nonce = os.urandom(12)
    return nonce


color = "#" + secrets.token_hex(3)
