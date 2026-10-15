import secrets

import numpy as np
from flask import request


def code():
    width = int(request.args.get("width", 6))
~>    return str(secrets.randbelow(10)).zfill(width)


def token():
    n = request.args.get("bytes", 16, type=int)
~>    return secrets.token_hex(n)


def matrix():
    dim = int(request.json["dim"])
~>    grid = np.zeros((dim, dim))
    return {"sum": float(grid.sum())}


def label():
    w = int(request.form.get("w"))
~>    return request.form["text"].ljust(w)
