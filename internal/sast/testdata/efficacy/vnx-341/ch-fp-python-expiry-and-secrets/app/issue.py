import secrets
import time


def issue():
    expires_at = time.time() + 3600
    token = secrets.token_urlsafe()
    issued = int(time.time())
    return {"token": token, "issued": issued, "expires_at": expires_at}
