from flask import request, jsonify


def ping():
    return "pong"


def handle_rpc():
    name = request.json["method"]
~>    result = globals()[name]()
    return jsonify(result=result)
