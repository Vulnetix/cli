from urllib.parse import urlparse

from flask import redirect, request


def login_done():
    next_url = request.args.get("next", "/")
~>    if "acme.com" in next_url:
        return redirect(next_url)
    return redirect("/")


def is_trusted_host(hostname):
~>    return hostname.endswith("acme.com")


def callback():
    host = urlparse(request.args["cb"]).netloc
    for allowed in ALLOWED_CALLBACK_HOSTS:
~>        if host.endswith(allowed):
            return True
    return False
