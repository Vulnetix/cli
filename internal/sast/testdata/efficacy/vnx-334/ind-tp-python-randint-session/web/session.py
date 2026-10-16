import random
import secrets


def start_session(store, user):
~>    session_id = random.randint(1000, 9999)
    store[session_id] = user.id
    return session_id


def issue_reset(user):
~>    reset_token = secrets.randbelow(1000000)
    user.reset_token = reset_token
    user.save()
    return reset_token
