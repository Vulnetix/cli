import runpy
from flask import Flask, request

app = Flask(__name__)


@app.route("/doc")
def doc():
    name = request.args.get("name")
    # runpy.run_path(name) would be dangerous here
    note = "never call runpy.run_path(name)"
    return note
