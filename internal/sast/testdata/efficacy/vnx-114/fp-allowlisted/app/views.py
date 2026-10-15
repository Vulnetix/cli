import ctypes
import importlib

from flask import Flask, request

app = Flask(__name__)
HANDLERS = {"csv": "app.handlers.csv", "pdf": "app.handlers.pdf"}
libc = ctypes.CDLL("libc.so.6")


@app.route("/export")
def export():
    kind = request.args.get("kind", "csv")
    if kind not in HANDLERS:
        return "bad", 400
    mod = importlib.import_module(HANDLERS[kind])
    json = importlib.import_module("json")
    return mod.render(json)
