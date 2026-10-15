from urllib.parse import urlparse

import requests
from flask import abort, request

ALLOWED_HOSTS = {"images.example.com"}


def fetch():
    url = request.args.get("url")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(url).content
