import os
import random
import secrets
import time

random.seed(os.urandom(16))


def new_session():
    started = time.time()
    session_id = secrets.token_urlsafe(32)
    return {"id": session_id, "started": started}
