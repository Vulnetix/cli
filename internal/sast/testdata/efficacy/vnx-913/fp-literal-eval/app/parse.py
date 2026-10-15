import ast
from flask import request


def parse():
    data = ast.literal_eval(request.args.get("v"))
    model.eval()
    return eval("1 + 1")
