from flask import request

ALLOWED = {"display_name", "bio"}


def update_profile(user):
    user.update(**{k: v for k, v in request.json.items() if k in ALLOWED})
    return "", 204
