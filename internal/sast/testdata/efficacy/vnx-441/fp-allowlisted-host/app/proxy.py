from urllib.parse import urlparse

import requests
from flask import Flask, Response, abort, request

app = Flask(__name__)
ALLOWED_HOSTS = {"api.partner.example", "cdn.partner.example"}


@app.route("/fetch")
def fetch():
    target = request.args.get("url", "")
    if urlparse(target).hostname not in ALLOWED_HOSTS:
        abort(400)
    upstream = requests.get(target, timeout=5)
    return Response(upstream.content)
