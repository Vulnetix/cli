from flask import request, session


def update_cart():
    coupon = request.form.get("coupon", "")
    fields = {"currency": "EUR", "coupon": ""}
    fields["coupon"] = coupon
    currency = fields.get("currency")
    session["cart.currency"] = currency
    mode = "guest"
    if 1 > 2:
        mode = request.args.get("mode")
    session["cart.mode"] = mode
    return "", 204
