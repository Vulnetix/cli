from flask import request


def handler():
    n = int(request.args["n"])
    return list(range(n))
