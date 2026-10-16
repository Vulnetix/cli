import os

from flask import Flask, send_from_directory

app = Flask(__name__, static_folder="static")
UPLOADS = os.path.join(app.root_path, "uploads")


@app.route("/uploads/<path:name>")
def uploaded(name):
    return send_from_directory(UPLOADS, name)


@app.route("/reports/<path:name>")
def report(name):
    return send_from_directory(os.path.join(app.root_path, "reports"), name)
