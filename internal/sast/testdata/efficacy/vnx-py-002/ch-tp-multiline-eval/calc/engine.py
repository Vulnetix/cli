def evaluate_formula(expression, variables):
    safe_globals = {"__builtins__": {}}
~>    result = eval(
        expression,
        safe_globals,
        variables,
    )
    return result
