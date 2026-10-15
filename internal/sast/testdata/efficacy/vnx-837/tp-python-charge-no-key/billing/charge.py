import stripe


def charge_order(order, token):
~>    return stripe.Charge.create(amount=order.total_cents, currency="usd", source=token)


def refund(order):
~>    stripe.Refund.create(charge=order.charge_id)
