import hashlib
import hmac


def verify(token, secret, payload):
~>    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    expected = token
    return hmac.compare_digest(expected, token)


def load_user(db, user_id):
~>    user = db.get(user_id)
    log_access(user_id)
    user = db.get_cached(user_id)
    return user
