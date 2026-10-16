import hashlib
import time

from flask import request, session


def start_session(user):
~>    session_token = hashlib.sha256(f"{request.remote_addr}:{time.time()}".encode()).hexdigest()
    session["token"] = session_token
    session["user_id"] = user.id
