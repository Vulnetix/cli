from urllib.parse import urlparse

import requests
from flask import Flask, Response, abort, request

app = Flask(__name__)
ALLOWED_HOSTS = {"cdn.example.com", "images.example.com"}


@app.route("/img")
def image_proxy():
    target = request.args.get("u", "")
    host = urlparse(target).hostname
    if host not in ALLOWED_HOSTS:
        abort(400)
    r = requests.get(target, timeout=5)
    return Response(r.content, content_type=r.headers.get("Content-Type"))
