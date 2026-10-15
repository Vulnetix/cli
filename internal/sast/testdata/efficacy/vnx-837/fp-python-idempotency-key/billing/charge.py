import stripe


def charge_order(order, token):
    return stripe.Charge.create(
        amount=order.total_cents,
        currency="usd",
        source=token,
        idempotency_key=f"order-{order.id}",
    )


def refund(order):
    opts = {"idempotency_key": f"refund-{order.id}"}
    stripe.Refund.create(charge=order.charge_id, **opts)
