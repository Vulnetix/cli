from flask import request


@app.route("/items")
def items():
    page = request.args.get("page", 1, type=int)
    try:
        size = int(request.args["size"])
        raw = request.args.get("offset")
        offset = int(raw)
    except (TypeError, ValueError):
        abort(400)
    return list_items(page, size, offset)
