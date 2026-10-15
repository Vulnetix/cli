from flask import request, jsonify

HANDLERS = {"ping": lambda: "pong"}


def resolve(name):
    # name comes from internal code, not from the request
    return globals()[name]


def handle():
    action = request.args.get("action")
    handler = HANDLERS.get(action)
    if handler is None:
        return jsonify(error="unknown"), 400
    return jsonify(result=handler())


def config_value():
    return globals()["DEBUG_DEFAULT"]
