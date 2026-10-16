from flask import redirect, url_for

ROUTES = {"home": "/", "billing": "/billing"}


def go(request):
    dest = ROUTES.get(request.args.get("to"), "/")
    # redirect(request.args.get("next")) would be an open redirect
    return redirect(url_for("index"))
