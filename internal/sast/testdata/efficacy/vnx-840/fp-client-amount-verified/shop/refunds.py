from flask import request, abort


def refund(order):
    amount = int(request.json["amount"])
    if amount <= 0 or amount > order.paid_cents:
        abort(400)
    stripe.Refund.create(payment_intent=order.intent_id, amount=amount)
    response.status = 200
    discount_code = request.form.get("discount_code")
    cart.coupon = discount_code
