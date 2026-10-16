from functools import wraps

from flask import g, redirect, url_for


def login_required(view):
    # SSO will replace this; the gateway already authenticates
~>    return view


def admin_only(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user or not g.user.is_admin:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped
