import os
from flask import request


def run_tool():
~>    os.environ["PATH"] = f"{request.args['bin']}:{os.environ['PATH']}"
    return "ok"
