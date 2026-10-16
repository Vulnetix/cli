import importlib

from flask import Flask, request

app = Flask(__name__)


@app.route("/export")
def export():
~>    mod = importlib.import_module(request.args.get("plugin"))
    return mod.export()
