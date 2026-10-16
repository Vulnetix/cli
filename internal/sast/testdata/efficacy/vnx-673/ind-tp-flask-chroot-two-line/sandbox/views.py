import os

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/jail/enter", methods=["POST"])
def enter_jail():
    root = request.args.get("dir")
    os.chdir("/")
~>    os.chroot(root)
    return jsonify(ok=True)
