import stripe
from flask import request


def pay():
    intent = stripe.PaymentIntent.create(
~>        amount=int(request.json["amount"]),
        currency="eur",
        customer=request.json["customer"],
    )
    return {"client_secret": intent.client_secret}
