import math

SAFE_ENV = dict(__builtins__={"len": len, "range": range}, math=math)


def run_plugin(source):
~>    exec(source, SAFE_ENV)
