from flask import abort, request

ITEMS = ["a", "b", "c"]


def get_item():
    idx = int(request.args.get("idx", 0))
    if idx not in range(len(ITEMS)):
        abort(404)
    return ITEMS[idx]


def get_page():
    page = int(request.args.get("page", 1))
    start = (page - 1) * 20
    return ITEMS[start:start + 20]
