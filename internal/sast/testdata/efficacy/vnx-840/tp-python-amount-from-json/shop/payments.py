import stripe
from flask import request


@app.post("/pay")
def pay():
    amount = int(request.json["amount"])
    intent = stripe.PaymentIntent.create(
~>        amount=amount,
        currency="usd",
    )
    return {"secret": intent.client_secret}


@app.post("/charge")
def charge():
~>    stripe.Charge.create(amount=request.form["total"], currency="usd", source=request.form["token"])
