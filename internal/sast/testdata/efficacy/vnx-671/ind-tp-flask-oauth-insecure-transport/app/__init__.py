import os

from flask import Flask
from flask_dance.contrib.github import make_github_blueprint

~>os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ["FLASK_SECRET_KEY"]
    blueprint = make_github_blueprint(scope="read:user")
    app.register_blueprint(blueprint, url_prefix="/login")
    return app
