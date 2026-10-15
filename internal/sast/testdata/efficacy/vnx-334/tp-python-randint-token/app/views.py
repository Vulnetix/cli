import random


def create_session(user):
~>    session_id = random.randint(1000, 9999)
    store(user, session_id)


def reset(user):
~>    user.reset_token = str(random.randint(0, 999_999))
    user.save()


def api_key():
~>    return {"api_key": random.randrange(10**8)}
