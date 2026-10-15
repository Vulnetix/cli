from flask import abort, request


def transfer(src, dst):
    amount = int(request.form["amount"])
    if amount <= 0 or amount > src.balance:
        abort(400)
    dst.balance += amount
    src.balance -= amount


def order(product):
    qty = max(1, int(request.args.get("qty", 1)))
    return product.price * qty


def add(product):
    quantity = int(request.form["quantity"])
    if not 0 < quantity <= 10:
        abort(400)
    return product.price * quantity
