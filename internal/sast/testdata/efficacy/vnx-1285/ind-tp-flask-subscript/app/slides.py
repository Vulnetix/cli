from flask import request

SLIDES = ["a", "b", "c"]


def show():
    idx = int(request.args.get("index", 0))
~>    return SLIDES[idx]
