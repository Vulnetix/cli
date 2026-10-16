import stripe
from flask import request

def pay():
    cents = request.form["amount"]
~>    return stripe.Charge.create(amount=cents, currency="usd", source=request.form["token"])
