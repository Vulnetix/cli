import os
from flask import Flask
from requests_oauthlib import OAuth2Session

~>os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)


def session():
    return OAuth2Session(client_id)
