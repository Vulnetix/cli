import stripe


def test_charge(stripe_mock):
    stripe.Charge.create(amount=100, currency="usd", source="tok_visa")
