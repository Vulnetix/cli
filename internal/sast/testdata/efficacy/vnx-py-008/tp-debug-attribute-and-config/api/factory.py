from flask import Flask


def create_app():
    api = Flask(__name__)
~>    api.debug = True
~>    api.config["DEBUG"] = True
~>    api.config.update(DEBUG=True, SECRET_KEY="dev")
    return api
