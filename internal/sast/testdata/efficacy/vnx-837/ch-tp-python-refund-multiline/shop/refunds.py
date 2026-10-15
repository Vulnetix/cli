import stripe


def refund_order(order):
~>    refund = stripe.Refund.create(
        payment_intent=order.payment_intent_id,
        amount=order.refund_cents,
        reason="requested_by_customer",
    )
    order.refund_id = refund.id
    order.save()


def pay_seller(seller, cents):
~>    return stripe.Transfer.create(amount=cents, currency="usd", destination=seller.account_id)
