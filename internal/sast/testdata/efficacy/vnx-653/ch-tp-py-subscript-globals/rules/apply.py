def apply_rule(rule_text, record):
    scope = {"record": record}
    scope["__builtins__"] = None
~>    return eval(rule_text, scope)
