import ast
import subprocess

TEMPLATE = "1 + 2"


def literal():
    return eval("1 + 2", {"__builtins__": {}})


def real_builtins(expr, scope):
    return eval(expr, {"__builtins__": __builtins__}, scope)


def default_globals(expr):
    return eval(expr)


def parsed(text):
    return ast.literal_eval(text)


def separate_process(path):
    return subprocess.run(["python", path], timeout=5, check=False)
