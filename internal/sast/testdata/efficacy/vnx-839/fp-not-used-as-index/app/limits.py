from flask import request


def page():
    size = int(request.args.get("size", "20"))
    if size > 100:
        size = 100
    return query.limit(size)
