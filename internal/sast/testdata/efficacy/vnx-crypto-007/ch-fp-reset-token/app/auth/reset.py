import hashlib
import secrets


def issue(user):
    password_reset_token = secrets.token_urlsafe(32)
    user.reset_digest = hashlib.sha256(password_reset_token.encode()).hexdigest()
    return password_reset_token
