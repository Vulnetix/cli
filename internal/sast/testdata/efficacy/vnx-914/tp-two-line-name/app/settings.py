from flask import request


def change(cfg):
    attr = request.args.get("name")
    value = request.args.get("value")
~>    setattr(cfg, attr, value)
    return "ok"
