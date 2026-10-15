import math

SAFE_GLOBALS = {"__builtins__": {}, "math": math}


def compute(formula, variables):
~>    return eval(formula, SAFE_GLOBALS, dict(variables))


def run_user_script(code):
    sandbox = {}
    sandbox["__builtins__"] = {"print": print}
~>    exec(compile(code, "<user>", "exec"), sandbox)
