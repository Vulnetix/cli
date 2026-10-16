from flask import request, abort

ITEMS = ["a", "b", "c"]

def a():
    idx = int(request.args.get("i", "0"))
    if not 0 <= idx < len(ITEMS):
        abort(404)
    return ITEMS[idx]

def b():
    idx = int(request.args.get("i", "0"))
    if idx < 0 or idx >= len(ITEMS):
        abort(404)
    return ITEMS[idx]

def c():
    idx = max(0, int(request.args.get("i", "0")))
    if idx < len(ITEMS):
        return ITEMS[idx]
