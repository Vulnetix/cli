from flask import session, request, abort


def login():
    user = authenticate(request.form["username"], request.form["password"])
    session["role"] = user.role
    session["is_admin"] = user.admin


def admin():
    if not session.get("is_admin"):
        abort(403)
    cookie_role = roles_for(request.cookies.get("session"))
    return cookie_role
