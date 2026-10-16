import uuid

INVITE_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def make_invite_code(email):
~>    return str(uuid.uuid5(INVITE_NS, email.lower()))
