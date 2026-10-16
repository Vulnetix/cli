from flask import abort, request


def restock(product):
    qty = int(request.form["quantity"])
    if qty <= 0 or qty > 1000:
        abort(400)
    product.stock += qty


def clamp_line(product):
    qty = max(1, min(int(request.form.get("quantity", 1)), 50))
    return product.price * qty
