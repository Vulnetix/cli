import ast
import builtins

from RestrictedPython import compile_restricted, safe_builtins


def literal(text):
    return ast.literal_eval(text)


def restricted(src):
    code = compile_restricted(src, "<rule>", "exec")
    exec(code, {"__builtins__": safe_builtins})


def debug(expr, ns):
    return eval(expr, {"__builtins__": builtins}, ns)


def const():
    # eval(user, {"__builtins__": {}}) is not a sandbox
    return eval("1 + 1", {"__builtins__": {}})
