def export():
    global __all__
    __all__ = ["export"]


def describe():
    """
    Example of what to avoid:

        def f():
            global counter
            counter += 1
    """
    return "ok"
