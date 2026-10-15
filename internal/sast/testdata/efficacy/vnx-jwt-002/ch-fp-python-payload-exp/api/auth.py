import datetime

import jwt


def issue(user, key):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user.id),
        "iat": now,
        "exp": now + datetime.timedelta(minutes=30),
    }
    return jwt.encode(payload, key, algorithm="HS256")
