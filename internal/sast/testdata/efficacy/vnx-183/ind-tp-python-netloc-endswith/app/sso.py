from urllib.parse import urlparse

from flask import abort, redirect, request


@app.route("/sso/callback")
def sso_callback():
    target = request.args.get("next", "/")
~>    if not urlparse(target).netloc.endswith("acme.com"):
        abort(400)
    return redirect(target)
