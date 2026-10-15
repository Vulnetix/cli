import stripe
from flask import request


def pay():
    product = Product.query.get(request.json["product_id"])
    amount = product.price_cents
    stripe.PaymentIntent.create(amount=amount, currency="usd")
