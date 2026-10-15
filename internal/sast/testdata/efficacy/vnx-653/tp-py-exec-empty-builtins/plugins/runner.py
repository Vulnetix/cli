def run_plugin(source, payload):
    scope = {"payload": payload}
~>    exec(source, {"__builtins__": {}}, scope)
    return scope.get("result")


def evaluate_rule(expression, facts):
~>    return eval(expression, {'__builtins__': None}, facts)


def evaluate_limited(expr):
~>    return eval(expr,
                {"__builtins__": {"len": len, "min": min, "max": max}})
