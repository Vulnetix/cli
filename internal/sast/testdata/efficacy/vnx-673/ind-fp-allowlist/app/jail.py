import os
from flask import Flask, request, abort

app = Flask(__name__)
JAILS = {"a": "/srv/jails/a", "b": "/srv/jails/b"}


@app.route("/enter")
def enter():
    name = request.args.get("name")
    if name not in JAILS:
        abort(400)
    target = JAILS[name]
    os.chroot(target)
    return "ok"


@app.route("/lang")
def lang():
    os.environ["LANG"] = request.args.get("lang", "C")
    return "ok"
