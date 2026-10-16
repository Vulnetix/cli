from flask import request

def update(user):
    setattr(user, "display_name", request.form["name"])
    for field in ("first_name", "last_name"):
        setattr(user, field, request.form[field])
