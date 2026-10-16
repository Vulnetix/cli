def refund(card, amount):
    """Refund a card.

    Args:
        card: token
        amount: cents

    Raises:
        ValueError: if amount is not positive.
    """
    if amount <= 0:
        raise ValueError("amount must be positive")
    return card.credit(amount)
