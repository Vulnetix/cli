import uuid


def issue(user):
~>    token = str(uuid.uuid1())
    user.save_token(token)


def invite_code():
~>    invite_token = uuid.uuid4().hex[:8]
    return invite_token


def session():
~>    return {"session_id": uuid.uuid1().hex}
