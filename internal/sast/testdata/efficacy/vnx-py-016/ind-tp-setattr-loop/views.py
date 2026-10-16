from flask import request, jsonify


def update_customer(customer):
    for key, value in request.get_json().items():
~>        setattr(customer, key, value)
    return jsonify(ok=True)
