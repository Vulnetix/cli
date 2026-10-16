import os
import datetime as dt
import jwt


def issue_token(user):
    payload = {
        "sub": str(user.id),
        "exp": dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30),
    }
    return jwt.encode(payload, os.environ["JWT_KEY"], algorithm="HS256")
