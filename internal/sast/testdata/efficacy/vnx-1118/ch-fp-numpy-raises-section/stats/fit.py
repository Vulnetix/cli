def fit(x, y):
    """Fit a line.

    Parameters
    ----------
    x, y : array
        Samples.

    Returns
    -------
    tuple
        Slope and intercept.

    Raises
    ------
    LinAlgError
        When the samples are degenerate.
    """
    if len(x) < 2:
        raise LinAlgError("need two samples")
    return solve(x, y)
