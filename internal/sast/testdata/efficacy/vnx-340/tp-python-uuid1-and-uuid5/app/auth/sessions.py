import uuid
from uuid import uuid1

~>session_id = str(uuid.uuid1())


def new_reset_token(user):
~>    return uuid.uuid5(uuid.NAMESPACE_DNS, user.email).hex


def new_api_key():
~>    raw = uuid1().hex
    api_key = "ak_" + raw
    return api_key
