import bcrypt
from django.core import signing

SESSION_SALT = "app.session.cookie"
SALT_LENGTH = 16
SALT_COLUMN = "password_salt"


def dump(data):
    return signing.dumps(data, salt=SESSION_SALT)


def verify(password: bytes, stored: bytes) -> bool:
    return bcrypt.hashpw(password, stored) == stored


def check(password: bytes, stored: bytes) -> bool:
    return bcrypt.checkpw(password, stored)


def columns(cursor):
    cursor.execute("SELECT %s FROM users" % SALT_COLUMN)
    return cursor.fetchall()
