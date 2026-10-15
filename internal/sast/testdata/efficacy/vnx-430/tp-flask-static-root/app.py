import os

from flask import Flask, send_from_directory

~>app = Flask(__name__, static_folder=".", static_url_path="")
~>legacy = Flask("legacy", static_folder=os.path.dirname(os.path.abspath(__file__)))


@app.route("/download/<path:filename>")
def download(filename):
~>    return send_from_directory(app.root_path, filename)


@app.route("/raw/<path:name>")
def raw(name):
~>    return send_from_directory(os.getcwd(), name)
