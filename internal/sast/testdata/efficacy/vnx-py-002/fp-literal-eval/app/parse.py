import ast
from ast import literal_eval


def parse_setting(raw):
    value = ast.literal_eval(raw)
    other = literal_eval(raw)
    return value, other


def safe_eval_disabled(raw):
    return my_eval(raw) + evaluate(raw) + medieval(raw)
