import json
from flask import request, abort


def parse():
    try:
        rows = json.loads(request.data)
    except ValueError:
        abort(400)
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        abort(400)
    return rows, page
