import jwt


def issue(user, key):
~>    return jwt.encode({"sub": user.username, "password_hash": user.password_hash}, key, algorithm="HS256")
