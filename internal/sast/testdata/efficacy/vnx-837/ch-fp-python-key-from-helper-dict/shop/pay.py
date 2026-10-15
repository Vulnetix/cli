import stripe


def pay(order):
    return stripe.PaymentIntent.create(
        amount=order.cents,
        currency="usd",
        customer=order.customer_id,
        idempotency_key=f"order-{order.id}",
    )
