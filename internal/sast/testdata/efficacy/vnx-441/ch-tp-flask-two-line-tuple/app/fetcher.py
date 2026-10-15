import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    target = request.args["url"]
    headers = {"User-Agent": "fetcher/1.0"}
~>    upstream = requests.get(target, headers=headers, timeout=5)
    return upstream.content, upstream.status_code
