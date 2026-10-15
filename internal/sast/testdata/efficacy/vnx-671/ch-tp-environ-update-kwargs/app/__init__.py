import os
from flask import Flask

~>os.environ.update(OAUTHLIB_INSECURE_TRANSPORT="1")


def create_app():
    app = Flask(__name__)
~>    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"
    return app
