def charge(card, amount):
    """Charge a card.

    Args:
        card: The stored card token.
        amount: Amount in cents.

    Returns:
        The provider transaction id.
    """
    if amount <= 0:
~>        raise ValueError(f"amount must be positive, got {amount}")
    if not card:
        raise ValueError("card is required")
    return _gateway.charge(card, amount)
