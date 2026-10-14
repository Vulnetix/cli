from datetime import datetime, timedelta, timezone

import jwt


def issue(user, key):
    return jwt.encode(
        {"sub": str(user.pk), "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
        key,
        algorithm="HS256",
    )


def issue_refresh(user, key):
    payload = {"sub": str(user.pk)}
    payload["exp"] = datetime.now(timezone.utc) + timedelta(days=1)
    return jwt.encode(payload, key, algorithm="HS256")


def read(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
