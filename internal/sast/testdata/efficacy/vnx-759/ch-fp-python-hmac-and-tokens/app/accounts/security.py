import hashlib
import hmac
import os

import bcrypt


def store_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))


def derive(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def mac(password: str, message: bytes) -> str:
    return hmac.new(password.encode(), message, hashlib.sha256).hexdigest()


def reset_digest(reset_token: str) -> str:
    return hashlib.sha256(reset_token.encode()).hexdigest()


def help_text():
    return "We never store hashlib.md5(password) values."
