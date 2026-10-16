import stripe

def test_charge(monkeypatch):
    stripe.Charge.create(amount=100, currency="usd", source="tok_visa")
