from flask import request, abort

ITEMS = ["a", "b", "c"]

def get_item():
    idx = int(request.args.get("i", "0"))
~>    if idx < len(ITEMS):
        return ITEMS[idx]
    abort(404)
