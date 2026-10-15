from flask import request


def item():
    idx = int(request.args.get("i", "0"))
    if 0 <= idx < len(ITEMS):
        return ITEMS[idx]


def slot():
    pos = int(request.form["pos"])
    if pos < 0 or pos >= MAX_SLOTS:
        abort(400)
    slots[pos] = 1


def other():
    n = int(request.args["n"])
    if n < 0:
        abort(400)
    if n < len(ROWS):
        return ROWS[n]
