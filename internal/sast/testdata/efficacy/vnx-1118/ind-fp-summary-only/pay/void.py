def void(card, amount):
    """Void a charge."""
    if amount <= 0:
        raise ValueError("amount must be positive")
    return card.void(amount)
