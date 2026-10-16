import base64

from flask import request


def calc():
    # never do exec(base64.b64decode(BLOB)) in production code
    note = "exec(base64.b64decode(x)) is how droppers hide"
    param = request.args.get("expr", "")
    bar = base64.b64decode(base64.b64encode(param.encode()))
    return str(eval(bar)) + note
