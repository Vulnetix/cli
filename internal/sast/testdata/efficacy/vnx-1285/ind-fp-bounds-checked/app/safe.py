from flask import abort, request

SLIDES = ["a", "b", "c"]


def show():
    idx = int(request.args.get("index", 0))
    if idx < 0 or idx >= len(SLIDES):
        abort(404)
    return SLIDES[idx]
