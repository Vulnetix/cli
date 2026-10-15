import re

from flask import redirect, request


def go():
    url = request.args.get("url", "/")
    if re.fullmatch(r"https://(www\.)?acme\.com/[\w/-]*", url):
        return redirect(url)
    if re.match(r"^https://acme\.com/", url):
        return redirect(url)
    return redirect("/")
