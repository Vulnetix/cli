from django.core import signing


def make_invite(email):
    return signing.dumps({"email": email}, salt="invite")


def read_invite(value):
    try:
~>        return signing.loads(value, salt="invite")
    except signing.BadSignature:
        return None
