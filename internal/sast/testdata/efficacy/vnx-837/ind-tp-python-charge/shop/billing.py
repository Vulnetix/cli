import stripe

def pay(order, token):
~>    return stripe.Charge.create(amount=order.total_cents, currency="usd", source=token)
