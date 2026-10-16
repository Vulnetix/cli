import hashlib

DEFAULT_ROLE = "viewer"
~>BACKDOOR_USER = "аdmin"


def is_admin(name):
    return name == "admin"
