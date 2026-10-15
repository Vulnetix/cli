from urllib.parse import urlparse

from flask import Flask, redirect, request, url_for

app = Flask(__name__)
SAFE = {"/dashboard", "/settings"}


@app.route("/to")
def to():
    target = request.args.get("t", "/")
    if target not in SAFE:
        target = "/"
    return redirect(target)


@app.route("/page")
def page():
    return redirect(url_for(request.args.get("endpoint", "index")))


@app.route("/ext")
def ext():
    dest = request.args.get("u", "")
    if urlparse(dest).netloc:
        return redirect("/")
    return redirect(dest)
