import builtins

LIMIT = eval("2 ** 10", {"__builtins__": {}})
ORIGINAL = builtins.__dict__["len"]


def describe():
    return {"__builtins__": "the module of built-in names"}
