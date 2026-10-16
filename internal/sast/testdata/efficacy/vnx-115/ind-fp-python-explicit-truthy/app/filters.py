from flask import request

from .util import str2bool


def read_filters():
    has_filters = bool(request.args)
    archived = request.args.get("archived", "").lower() == "true"
    beta = request.args.get("beta", type=str2bool)
    has_files = bool(request.files)
    payload = request.get_json(silent=True) or {}
    pinned = bool(payload.get("pinned"))
    return has_filters, archived, beta, has_files, pinned
