def evaluate(expression, x):
~>    return eval(
        expression,
        {"__builtins__": {}},
        {"x": x},
    )
