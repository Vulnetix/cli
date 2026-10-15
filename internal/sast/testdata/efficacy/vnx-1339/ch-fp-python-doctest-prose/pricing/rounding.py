import math


def nearly_equal(a, b):
    """Compare two floats with a tolerance.

    Exact comparison fails for decimals such as:

    >>> 0.1 + 0.2 == 0.3
    False
    >>> nearly_equal(0.1 + 0.2, 0.3)
    True
    """
    return math.isclose(a, b, rel_tol=1e-9)
