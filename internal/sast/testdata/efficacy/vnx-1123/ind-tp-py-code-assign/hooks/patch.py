def original():
    return 1


def other():
    return 2


~>original.__code__ = other.__code__
