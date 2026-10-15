from flask import request


def listing():
    if request.args.get("sort") == "price":
        items = sorted(load(), key=lambda i: i.price)
    else:
        items = load()
    if request.args.get("format") == "json":
        return jsonify(items)
    return render(items)
