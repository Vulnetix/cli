import hashlib
import hmac


def login(request):
    user = load(request.form["email"])
    candidate = hashlib.sha256(request.form["password"].encode()).hexdigest()
    if not hmac.compare_digest(candidate, user.password_hash):
        abort(401)


def login2(request):
    user = load(request.form["email"])
    if hash_password(request.form["password"], user.salt) != user.password_hash:
        abort(401)


def login3(request):
    pw = request.form["password"]
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), user.salt, 600000).hex()
    if digest == user.password_hash:
        return ok()
