from urllib.parse import urlparse

from flask import redirect, request


def callback():
    target = request.args.get("next", "/")
~>    if urlparse(target).netloc.endswith("acme.com"):
        return redirect(target)
    return redirect("/")
