import requests
from urllib.parse import urlparse
from flask import request

def get():
    url = request.args.get("url")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(url, timeout=5).status_code
