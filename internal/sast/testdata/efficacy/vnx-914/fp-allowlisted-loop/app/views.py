from flask import request

EDITABLE = {"bio", "display_name"}


def patch(user):
    for key, value in request.json.items():
        if key not in EDITABLE:
            continue
        setattr(user, key, value)
    for key, value in request.form.items():
        if key in EDITABLE:
            setattr(user, key, value)
