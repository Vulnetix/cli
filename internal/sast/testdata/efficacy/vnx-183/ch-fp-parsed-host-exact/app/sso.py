from urllib.parse import urlparse

from flask import redirect, request

ALLOWED_HOSTS = {"acme.com", "www.acme.com"}


def callback():
    target = request.args.get("next", "/")
    if urlparse(target).netloc in ALLOWED_HOSTS:
        return redirect(target)
    if urlparse(target).netloc.endswith(".acme.com"):
        return redirect(target)
    return redirect("/")
