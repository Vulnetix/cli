from flask import Flask, jsonify

from . import actions

app = Flask(__name__)


@app.route("/run/<name>")
def run(name):
~>    fn = getattr(actions, name)
    return jsonify(fn())


@app.get("/mod/{module}")
async def load(module: str):
    import importlib
~>    m = importlib.import_module(module)
    return {"name": m.__name__}
