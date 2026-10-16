import os

from flask import Flask, abort, request

app = Flask(__name__)

JAILS = {"a": "/srv/jails/a", "b": "/srv/jails/b"}


@app.post("/jail")
def jail():
    name = request.args.get("name")
    if name not in JAILS:
        abort(400)
    jail_root = JAILS[name]
    os.chroot(jail_root)
    return "ok"
