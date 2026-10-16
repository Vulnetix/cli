from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024
~>    app.config["MAX_FORM_PARTS"] = None
    return app
