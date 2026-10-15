import base64


def save(user, password):
    user.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    digest = base64.b64encode(hashlib.sha256(password.encode()).digest())
    salt = base64.b64encode(os.urandom(16))
    data = base64.b64encode(payload)
    hashed = base64.b64encode(password_hash)
