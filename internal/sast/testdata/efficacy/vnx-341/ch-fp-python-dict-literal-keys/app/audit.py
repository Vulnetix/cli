import secrets
import time


def audit_entry(user):
    ts = int(time.time())
    api_key = secrets.token_hex(32)
    return {"api_key": api_key, "ts": ts, "user": user}
