import os

from flask import request


def listing():
    page = request.args.get("page", 1)
    if page == 1:
        return "first page"
    size = len(request.args.get("q", ""))
    if size == 0:
        return "empty query"
    workers = os.environ.get("WORKERS", 4)
    if workers == 4:
        return "default"
    return "other"
