from .models import User


def login(request):
    user = User.query.filter_by(name=request.form["username"]).first()
~>    if user and user.password == request.form["password"]:
        return start_session(user)
    return None


def check(stored_password, supplied):
~>    return supplied == stored_password


def check_row(row, pw):
~>    if row['password'] != pw:
        raise PermissionError("bad credentials")
