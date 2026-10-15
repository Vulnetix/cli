import os

from flask import Flask, send_from_directory

app = Flask(__name__)


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.root_path, "favicon.ico", mimetype="image/vnd.microsoft.icon")


@app.route("/robots.txt")
def robots():
    return send_from_directory(os.getcwd(), 'robots.txt')


@app.route("/media/<path:name>")
def media(name):
    return send_from_directory(os.path.join(app.root_path, "media"), name)
