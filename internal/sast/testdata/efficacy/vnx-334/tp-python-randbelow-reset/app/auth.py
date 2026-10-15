import secrets


def make_reset_token():
~>    reset_token = secrets.randbelow(1000000)
    return reset_token


def make_invite():
~>    invite_token = f"{secrets.randbelow(2**20):06d}"
    return invite_token
