import stripe


def charge(card_token, cents):
    # TODO: add an idempotency key here once orders carry ids
~>    return stripe.Charge.create(amount=cents, currency="usd", source=card_token)
