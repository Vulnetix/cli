from werkzeug.security import check_password_hash


def login():
    user = find(request.form["email"])
    if not check_password_hash(user.password_hash, request.form["password"]):
        abort(401)
    if user.password_hash == "":
        abort(403)
