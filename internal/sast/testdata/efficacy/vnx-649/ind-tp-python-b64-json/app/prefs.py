import base64
import json
from flask import request

def load_prefs():
~>    prefs = json.loads(base64.b64decode(request.cookies["profile"]))
    return prefs
