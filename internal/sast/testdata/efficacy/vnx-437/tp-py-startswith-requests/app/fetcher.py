import requests
from flask import Flask, request, abort

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url.startswith("https://api.partner-data.com"):
        abort(400)
~>    resp = requests.get(url, timeout=5)
    return resp.text


@app.route("/avatar")
def avatar():
    image_url = request.args["src"]
    if "avatars.acme.example.com" in image_url:
~>        return requests.request("GET", image_url).content
    abort(404)
