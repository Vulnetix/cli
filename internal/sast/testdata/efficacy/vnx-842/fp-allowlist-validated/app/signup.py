from flask import abort, request

SELF_SERVICE_ROLES = {"viewer", "contributor"}


def signup():
    role = request.json.get("role", "viewer")
    if role not in SELF_SERVICE_ROLES:
        abort(400)
    user = User(email=request.json["email"], role=role)
    db.session.add(user)
    return user
