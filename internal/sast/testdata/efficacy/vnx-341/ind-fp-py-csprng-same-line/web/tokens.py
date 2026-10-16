import secrets
import time


def new_reset_token():
    token = secrets.token_urlsafe(32) + "." + str(int(time.time()))
    return token
