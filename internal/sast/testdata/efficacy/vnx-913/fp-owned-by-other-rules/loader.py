import ctypes
import importlib
from flask import Flask, request

app = Flask(__name__)


@app.route("/x")
def x():
    p = request.args.get("p")
    ctypes.CDLL(p)
    importlib.import_module(request.args["m"])
    code = open(p).read()
    exec(code)
    exec(open(p).read())
    return "ok"
