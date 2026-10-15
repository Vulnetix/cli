import base64
import json

from flask import request


def current_role():
~>    data = json.loads(base64.b64decode(
        request.cookies["identity"]
    ))
    return data["role"]
