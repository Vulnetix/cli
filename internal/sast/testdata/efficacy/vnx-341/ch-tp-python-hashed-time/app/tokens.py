import hashlib
import time


def new_reset_token():
~>    token = hashlib.sha256(str(time.time()).encode()).hexdigest()
    return token
