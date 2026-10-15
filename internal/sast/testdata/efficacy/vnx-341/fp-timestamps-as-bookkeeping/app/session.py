import secrets
import time
from datetime import datetime


def touch(session, token_expiry):
    session["last_activity"] = time.time()
    token_created_at = datetime.utcnow()
    if time.time() > token_expiry:
        return None
    token = secrets.token_hex(16) + str(int(time.time()))
    return token, token_created_at
