import re

from flask import redirect, request


def go():
    url = request.args.get("url", "/")
~>    if re.match(r"https://(www\.)?acme\.com", url):
        return redirect(url)
    return redirect("/")
