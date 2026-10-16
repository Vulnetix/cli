import re
from flask import request, redirect

~>ALLOWED = re.compile(r"^https?://accounts.example.com/")


def go():
    url = request.args.get("next", "/")
~>    if re.match(r"^https?://accounts.example.com/login", url):
        return redirect(url)
    return redirect("/")
