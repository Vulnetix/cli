def charge(card, amount):
    """Charge a card.

    Args:
        card: The stored card token.
        amount: Amount in cents.

    Returns:
        The receipt id.
    """
    if amount <= 0:
~>        raise ValueError("amount must be positive")
    return card.bill(amount)
