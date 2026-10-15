import os

from flask import request


def search():
    q = request.args.get("q", os.environ["DEFAULT_QUERY"])
    limit = int(os.environ.get("LIMIT", "10"))
    os.environ["LAST_BOOT"] = "1"
    return q, limit
