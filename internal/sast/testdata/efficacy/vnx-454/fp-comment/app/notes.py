from flask import request


def handler():
    # Never do this: is_admin = request.cookies.get("admin") == "1"
    # if request.args.get("admin"): grant()
    return request.args.get("page", "1")
