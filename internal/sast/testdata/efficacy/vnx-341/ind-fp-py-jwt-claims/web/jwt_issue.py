import time

import jwt


def issue_access_token(user, key):
    now = int(time.time())
    claims = {"sub": str(user.id), "iat": now, "exp": now + 900}
    return jwt.encode(claims, key, algorithm="RS256")
