from flask import request

HANDLERS = {"a": 1}


def lookup():
    name = request.args.get("name")
    globals()["LAST_LOOKUP"] = name
    handler = HANDLERS.get(name)
    return str(handler)


def setup(config):
    for key, value in config.items():
        globals()[key] = value
