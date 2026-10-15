import importlib

from flask import Flask, request

app = Flask(__name__)


@app.route("/plugin")
def run_plugin():
~>    mod = importlib.import_module(request.args.get("plugin"))
    return mod.run()


@app.route("/backend", methods=["POST"])
def select_backend():
    name = request.form["backend"]
~>    backend = __import__(name)
    module_path = f"app.exporters.{request.json['format']}"
~>    exporter = importlib.import_module(
        module_path
    )
    return backend.describe() + exporter.export()
