import random
import secrets


def new_session(store):
~>    session_id = random.randint(1000, 9999)
    store[session_id] = {}
    return session_id


def api_token():
~>    api_token = str(random.randrange(1000000))
    return api_token


def reset_secret():
~>    reset_key = secrets.randbits(16)
    return reset_key
