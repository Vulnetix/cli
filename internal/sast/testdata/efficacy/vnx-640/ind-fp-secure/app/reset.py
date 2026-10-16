import secrets
import random
import time


def start_reset(user, settings):
    token = secrets.token_urlsafe(32)
    link = f"{settings.PUBLIC_BASE_URL}/reset/{token}"
    user.reset_token_created = time.time()
    return link


def backoff(attempt):
    jitter = random.random()
    return attempt * 2 + jitter
