from urllib.parse import urlparse

from flask import abort, redirect, request

ALLOWED_HOSTS = {"acme.com", "app.acme.com"}


@app.route("/go")
def go():
    target = request.args.get("next", "/")
    hostname = urlparse(target).hostname or ""
    if hostname == "acme.com" or hostname.endswith(".acme.com"):
        return redirect(target)
    if hostname in ALLOWED_HOSTS:
        return redirect(target)
    abort(400)
