from flask import request


def update(user):
    setattr(user, "email", request.form["email"])
    for field in ("first_name", "last_name"):
        setattr(user, field, request.form.get(field))
