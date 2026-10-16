from flask import flash, redirect, url_for
from werkzeug.security import generate_password_hash


def do_login(form, user):
    candidate = generate_password_hash(form.password.data)
~>    if candidate == user.pw_hash:
        login_user(user)
        return redirect(url_for("main.index"))
    flash("Invalid username or password")
    return redirect(url_for("auth.login"))
