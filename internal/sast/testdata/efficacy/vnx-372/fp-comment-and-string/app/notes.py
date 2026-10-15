# Bug pattern: if s.find("x"): treats index 0 as not found
HELP = "never write if name.find('x'): in production code"


def ok(name):
    """Example: if name.find("x"): is wrong."""
    return name.find("x") >= 0
