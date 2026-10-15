from flask import request


def requested_limit():
    raw = request.args.get("limit", "10")
~>    return int(raw, base = 0)


def requested_mask(value):
~>    return int(value,0)
