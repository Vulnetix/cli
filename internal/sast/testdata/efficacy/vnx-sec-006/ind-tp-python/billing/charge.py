import stripe

~>stripe.api_key = "@@sample:sk_live_[A-Za-z0-9]{24}@@"

def charge(amount):
    return stripe.PaymentIntent.create(amount=amount, currency="usd")
