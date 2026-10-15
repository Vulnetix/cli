import hashlib
import time


def start(request):
~>    token = hashlib.md5(str(time.time()).encode()).hexdigest()
~>    session_id = f"{request.remote_addr}-{int(time.time())}"
    return token, session_id


def make_nonce():
~>    return str(time.time_ns())
