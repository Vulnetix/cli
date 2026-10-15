import json
from base64 import urlsafe_b64decode

from flask import g, request


def load_user():
~>    claims = json.loads(urlsafe_b64decode(request.headers["X-Auth-Token"]))
    g.user_id = claims["sub"]
