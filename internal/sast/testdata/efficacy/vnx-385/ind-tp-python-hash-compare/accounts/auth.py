import hashlib

from .db import fetch_user


def _derive(candidate: str, salt: str) -> str:
    return hashlib.sha256((salt + candidate).encode("utf-8")).hexdigest()


def verify(username: str, candidate: str) -> bool:
    row = fetch_user(username)
    if row is None:
        return False
    computed = _derive(candidate, row["salt"])
~>    return row["password"] == computed


def verify_legacy(user, candidate):
    expected = _derive(candidate, user.salt)
~>    if user.hashed_password != expected:
        raise PermissionError("bad credentials")
    return True
