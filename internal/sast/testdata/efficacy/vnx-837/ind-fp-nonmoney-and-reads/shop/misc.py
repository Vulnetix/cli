import stripe

def sync(user):
    c = stripe.Customer.create(email=user.email)
    p = stripe.Product.create(name="Pro plan")
    got = stripe.Charge.retrieve("ch_123")
    all_ = stripe.Refund.list(limit=3)
    return c, p, got, all_
