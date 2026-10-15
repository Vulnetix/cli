from flask import request


def apply_coupon(cart):
    pct = float(request.form.get("discount_percent", 0))
~>    cart.total = cart.subtotal * (1 - pct / 100)
    db.session.commit()
