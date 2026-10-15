import random
import secrets
import time

random.seed()
started = time.time()


def new_api_key():
    api_key = secrets.token_hex(32)
    return api_key
