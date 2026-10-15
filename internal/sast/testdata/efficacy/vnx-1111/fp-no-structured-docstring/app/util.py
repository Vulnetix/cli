def clamp(value, low, high):
    """Clamp value between low and high."""
    return max(low, min(high, value))


def noop(a, b):
    return None
