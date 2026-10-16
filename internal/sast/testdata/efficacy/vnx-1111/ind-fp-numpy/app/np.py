def scale(values, factor, offset):
    """Scale values.

    Parameters
    ----------
    values : list
        Input numbers.
    factor : float
        Multiplier.
    """
    return [v * factor + offset for v in values]
