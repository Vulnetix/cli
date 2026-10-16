import ast

from flask import jsonify, request


def parse_filters():
    filters = ast.literal_eval(request.args.get("filters", "{}"))
    page = int(request.args.get("page", "1"))
    offset = eval("(%d - 1) * 50" % page)
    return jsonify(filters=filters, offset=offset)


def evaluate_default():
    expr = "60 * 60 * 24"
    return eval(expr)
