import stripe

def refund(payment):
    result = (
~>        stripe.Refund.create(
            payment_intent=payment.intent_id,
            amount=payment.amount,
        )
    )
    return result
