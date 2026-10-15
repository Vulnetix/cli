import os
import secrets


def issue_api_key():
~>    api_key = secrets.token_hex(8)
    return api_key


def issue_reset(user):
~>    user.reset_token = secrets.token_urlsafe(6)
    user.save()


def new_session_id():
~>    session_id = os.urandom(4).hex()
    return session_id
