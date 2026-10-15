import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/sandbox", methods=["POST"])
def sandbox():
~>    os.chroot(request.form["root"])
    return "ok"


@app.route("/jail")
def jail():
    root = request.args.get("dir")
    os.chdir("/")
~>    os.chroot(root)
    return "ok"
