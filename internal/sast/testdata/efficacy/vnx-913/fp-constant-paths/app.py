import runpy
from importlib.machinery import SourceFileLoader
from flask import Flask, request

app = Flask(__name__)


@app.route("/migrate")
def migrate():
    who = request.args.get("who")
    runpy.run_path("/srv/migrations/latest.py")
    SourceFileLoader("seed", "/srv/seed.py").load_module()
    return who
