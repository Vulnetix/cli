import bcrypt
import hashlib


def register():
    rounds = request.json.get("rounds")
~>    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(request.json["password"].encode(), salt)


def derive():
    iterations = int(request.form["iterations"])
~>    return hashlib.pbkdf2_hmac("sha256", secret, salt, iterations)
