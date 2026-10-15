import random
import secrets
import time
import uuid


def start_reset(user):
    reset_token = secrets.token_urlsafe(32)
    user.reset_token_created = time.time()
    reset_id = uuid.uuid4().hex
    delay = random.random() * 2
    time.sleep(delay)
    return reset_token, reset_id
