import json
from base64 import urlsafe_b64decode
from flask import request


def claims():
~>    data = json.loads(urlsafe_b64decode(request.headers["X-Auth-Token"]))
    return data
