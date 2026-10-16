from flask import abort, request, session

from app.models import User


def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    if user is None or not user.check_password(request.form["password"]):
        abort(401)
    supplied = request.form["password"]
    if len(supplied) < 12:
        abort(400)
    session["uid"] = user.id
    return "ok"
