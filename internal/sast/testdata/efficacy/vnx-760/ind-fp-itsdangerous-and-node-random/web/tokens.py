from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer("key", salt="email-confirm")

SALT_COLUMN = "salt"
SALT_LEN = 16


def token(email):
    return serializer.dumps(email)
