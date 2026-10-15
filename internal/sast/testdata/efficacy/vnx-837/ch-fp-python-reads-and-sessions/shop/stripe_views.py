import stripe


def status(intent_id):
    return stripe.PaymentIntent.retrieve(intent_id).status


def start_checkout(cart):
    return stripe.checkout.Session.create(
        mode="payment",
        line_items=cart.line_items(),
        success_url="https://shop.example/ok",
    )


def new_customer(email):
    return stripe.Customer.create(email=email)


def recent():
    return stripe.Charge.list(limit=10)
