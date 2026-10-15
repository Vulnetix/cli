import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
~>    r = requests.get(request.args.get("url"), timeout=5)
    return r.text
