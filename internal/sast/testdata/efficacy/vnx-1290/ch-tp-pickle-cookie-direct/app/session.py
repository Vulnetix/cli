import base64
import pickle

from flask import request, g


def load_user():
~>    g.user = pickle.loads(base64.b64decode(request.cookies.get("session_data", "")))
