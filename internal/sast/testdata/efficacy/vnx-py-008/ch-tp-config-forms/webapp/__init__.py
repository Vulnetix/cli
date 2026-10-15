from flask import Flask


def create_app():
    app = Flask(__name__)
~>    app.config["DEBUG"] = True
~>    app.config.update(DEBUG=True, SECRET_KEY="x")
    return app
