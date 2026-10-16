def mean(values):
    """
    Compute the mean.

    Parameters
    ----------
    values : list of float
        The samples.

    Returns
    -------
    float
        The arithmetic mean.
    """
    if not values:
~>        raise ZeroDivisionError("no samples")
    return sum(values) / len(values)
