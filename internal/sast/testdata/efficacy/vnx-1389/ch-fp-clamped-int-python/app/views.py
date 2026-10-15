from flask import request


def page_number():
    page = max(int(request.args.get("page", 1)), 0)
    size = min(int(request.args.get("size", 20)), 100)
    return page, size


def offset(count):
    return round(int(count) / 2, 0)


def hexval(token):
    return int(token, 16)
