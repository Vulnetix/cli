import uuid
from uuid import uuid1


def start_password_reset(user):
~>    reset_token = str(uuid.uuid1())
    user.reset_token = reset_token


def login(user):
~>    session_id = uuid1().hex
    return session_id
