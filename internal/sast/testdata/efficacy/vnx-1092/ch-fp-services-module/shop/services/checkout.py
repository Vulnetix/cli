from flask import request, session


def cart_from_request():
    items = request.json.get("items", [])
    session["cart"] = items
    return items
