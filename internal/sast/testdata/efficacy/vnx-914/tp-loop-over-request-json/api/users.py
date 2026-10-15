from flask import request


def patch(user):
    for k, v in request.get_json().items():
~>        setattr(
            user, k, v)
    return user
