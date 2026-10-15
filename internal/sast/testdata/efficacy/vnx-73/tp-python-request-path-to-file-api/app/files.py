import os

from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
~>    return send_file(request.args.get("path"))


@app.route("/view")
def view():
    full = os.path.join(BASE, request.args["name"])
~>    with open(full) as fh:
        return fh.read()


@app.route("/raw/<name>")
def raw(name):
~>    return open(BASE + "/" + name, "rb").read()


@app.route("/delete", methods=["POST"])
def delete():
~>    os.remove(os.path.join(BASE,
                           request.form["file"]))
    return "", 204
