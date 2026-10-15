from urllib.parse import urlparse
from flask import redirect, request


def go():
    nxt = request.args.get("next", "/")
~>    if urlparse(nxt).netloc.endswith("example.com"):
        return redirect(nxt)
    return redirect("/")
