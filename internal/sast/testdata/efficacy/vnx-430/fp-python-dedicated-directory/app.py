import os

from fastapi.staticfiles import StaticFiles
from flask import Flask, send_from_directory

app = Flask(__name__, static_folder="static/")
api_static = StaticFiles(directory="static")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")


@app.errorhandler(Exception)
def handle_error(exc):
    return {"error": "internal"}, 500


@app.route("/files/<name>")
def files(name):
    return send_from_directory(UPLOAD_DIR, name)


# app = Flask(__name__, static_folder=".")
HELP = 'Flask(__name__, static_folder=".") serves your source'
