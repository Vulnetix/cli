import requests
from flask import request


def register_hook():
    callback = request.json["callback_url"]
~>    requests.post(callback, json={"event": "registered"}, timeout=5)
    return "", 204
