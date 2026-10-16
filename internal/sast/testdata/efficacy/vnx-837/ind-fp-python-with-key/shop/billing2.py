import stripe

def pay(order, token):
    return stripe.Charge.create(amount=order.total_cents, currency="usd", source=token,
                                idempotency_key=f"order-{order.id}")

def pay_multi(order, token):
    key = f"charge-{order.id}"
    return stripe.PaymentIntent.create(
        amount=order.total_cents,
        currency="usd",
        idempotency_key=key,
    )
