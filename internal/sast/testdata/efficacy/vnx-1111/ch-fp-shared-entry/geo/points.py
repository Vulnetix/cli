def distance(x1, y1, x2, y2, scale=1.0):
    """Euclidean distance between two points.

    Args:
        x1, y1: the first point.
        x2, y2: the second point.
        scale: multiplier applied to the result.
    """
    return scale * ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
