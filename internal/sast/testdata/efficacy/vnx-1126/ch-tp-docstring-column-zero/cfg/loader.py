CONFIG = {}


def load(path):
    """Load the configuration.

Lines of this docstring start at column zero, which some
projects do for long help text.
"""
~>    global CONFIG
    with open(path) as fh:
        CONFIG = parse(fh.read())
    return CONFIG
