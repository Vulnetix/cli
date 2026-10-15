import os

from flask import request


def page():
    n = request.args.get("page", type=int)
    if n == 1:
        return first()
    level = int(request.args.get("level", "0"))
    if level == 0:
        return none()
    debug = os.environ.get("DEBUG")
    if debug == "1":
        verbose()
    if int(input("n? ")) == 3:
        return three()
    count = len(request.args)
    return count == 0
