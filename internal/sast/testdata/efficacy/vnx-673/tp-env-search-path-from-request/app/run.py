import os
from flask import request


def run_tool():
    extra = request.json.get("libdir")
~>    os.environ["LD_LIBRARY_PATH"] = extra
~>    os.environ["PATH"] = request.args["bin"] + ":" + os.environ["PATH"]
    os.environ["LANG"] = request.args.get("lang", "C")
