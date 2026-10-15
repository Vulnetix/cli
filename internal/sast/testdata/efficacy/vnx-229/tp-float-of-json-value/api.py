from flask import request, jsonify


def price():
    body = request.get_json()
~>    discount = float(request.json["discount"])
~>    total = float(body["total"])
    return jsonify(total=total * (1 - discount))
