import datetime

import jwt

KEY = "unused"


def access_token(user):
    token = jwt.encode({"sub": user.id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, KEY, algorithm="HS256")
    return token


def refresh_token(user):
~>    token = jwt.encode({"sub": user.id, "type": "refresh"}, KEY, algorithm="HS256")
    return token
