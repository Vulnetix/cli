import uuid


def new_session():
~>    session_id = uuid.uuid1().hex
    return session_id


def invite_token():
~>    token = str(uuid.uuid4())[:8]
    return token
