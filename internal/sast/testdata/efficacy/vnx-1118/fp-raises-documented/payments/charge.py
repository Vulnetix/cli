def charge(card, amount):
    """Charge a card.

    Args:
        card: The stored card token.
        amount: Amount in cents.

    Raises:
        ValueError: if amount is not positive.
    """
    if amount <= 0:
        raise ValueError("amount must be positive")
    return _gateway.charge(card, amount)


def verify(token):
    """
    :param token: the encoded token
    :raises AuthError: when the signature is wrong
    """
    raise AuthError("bad signature")


def lookup(key):
    """Return the value.

    Parameters
    ----------
    key : str

    Raises
    ------
    KeyError
    """
    raise KeyError(key)


def parse(text):
    """Parse text.

    Args:
        text: input. A ParseError is returned to the caller on bad input.
    """
    raise ParseError(text)
