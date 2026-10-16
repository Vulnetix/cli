import math

SAFE_GLOBALS = {"__builtins__": None, "sqrt": math.sqrt, "pi": math.pi}


def evaluate(formula, variables):
~>    return eval(formula, SAFE_GLOBALS, dict(variables))
