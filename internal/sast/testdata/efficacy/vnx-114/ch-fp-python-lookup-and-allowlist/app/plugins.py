import importlib

from flask import Flask, abort, request

app = Flask(__name__)

BACKENDS = {"s3": "storage.s3", "gcs": "storage.gcs"}
ALLOWED = {"markdown", "rst"}


@app.get("/store")
def store():
    module = importlib.import_module(BACKENDS[request.args["backend"]])
    return module.status()


@app.get("/render")
def render():
    kind = request.args.get("kind", "markdown")
    if kind not in ALLOWED:
        abort(400)
    renderer = importlib.import_module(kind)
    return renderer.render(request.args.get("text", ""))
