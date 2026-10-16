def build(name, **kwargs):
    """Build a thing.

    Args:
        name: the name
        colour: passed through kwargs
        size: passed through kwargs
    """
    return make(name, **kwargs)
