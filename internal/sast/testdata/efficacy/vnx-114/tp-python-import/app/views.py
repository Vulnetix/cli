import ctypes
import importlib

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    name = request.args.get("module")
~>    mod = importlib.import_module("app.handlers." + name)
~>    lib = ctypes.CDLL(request.args["lib"])
~>    legacy = __import__(request.form.get("legacy"))
~>    other = ctypes.cdll.LoadLibrary(f"/opt/libs/{request.args['so']}")
    return str((mod, lib, legacy, other))
