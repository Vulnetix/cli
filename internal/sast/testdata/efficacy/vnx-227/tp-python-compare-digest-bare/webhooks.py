import hmac
import bcrypt
from werkzeug.security import check_password_hash


def receive(request, secret):
    sig = request.headers["X-Signature"]
    expected = hmac.new(secret, request.data, "sha256").hexdigest()
~>    hmac.compare_digest(sig, expected)
    return handle(request.json)


def login(user, password):
~>    bcrypt.checkpw(password.encode(), user.pw_hash)
~>    check_password_hash(user.pw_hash, password)
    session["uid"] = user.id
