from flask import request


def page():
    try:
        n = int(request.args.get("n"))
    except (TypeError, ValueError):
        n = 1
    return str(n)
