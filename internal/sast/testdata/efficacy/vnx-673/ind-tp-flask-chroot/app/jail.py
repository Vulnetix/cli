import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/enter")
def enter():
    root = request.args.get("dir")
~>    os.chroot(root)
    return "ok"
