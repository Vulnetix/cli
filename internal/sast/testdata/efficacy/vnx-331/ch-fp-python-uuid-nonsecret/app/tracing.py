import uuid


def trace_id():
    return uuid.uuid1().hex


def short_ref():
    ref = uuid.uuid4().hex[:8]
    return ref


def api_token():
    token = uuid.uuid4().hex
    return token
