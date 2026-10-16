from flask import redirect, session, url_for
from django.http import HttpResponseRedirect


def view():
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    return "secret"


def other(request):
    resp = HttpResponseRedirect("/x")
    resp["X-Foo"] = "1"
    return resp
