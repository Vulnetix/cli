from flask import request


def edit(user):
~>    user.__dict__.update(request.get_json())
    return user
