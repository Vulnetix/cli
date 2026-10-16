import base64
import marshal as m
import types
import urllib.request

import requests
from flask import Flask, request
from marshal import loads

app = Flask(__name__)


@app.route("/hook", methods=["POST"])
def install_hook():
    raw = base64.b64decode(request.form["code"])
~>    code = m.loads(raw)
    return types.FunctionType(code, {})()


@app.route("/inline", methods=["POST"])
def inline_hook():
~>    code = loads(
        request.get_data()
    )
    return str(code)


def fetch_plugin(url):
    resp = requests.get(url, timeout=10)
    body = resp.content
~>    return m.loads(body)


def fetch_bootstrap(url):
~>    return m.loads(urllib.request.urlopen(url).read())


def cached_plugin(path):
    with open(path, "rb") as fh:
        return m.loads(fh.read())
