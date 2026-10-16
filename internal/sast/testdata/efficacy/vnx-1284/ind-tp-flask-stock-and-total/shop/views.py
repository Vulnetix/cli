from flask import request


def restock(product):
~>    product.stock += int(request.form["quantity"])
    return "ok"


def price_line(product):
    qty = int(request.form.get("quantity", 1))
~>    total = product.price * qty
    return total
