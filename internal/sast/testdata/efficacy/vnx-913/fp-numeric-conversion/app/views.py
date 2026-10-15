from flask import request


def view():
    n = int(request.args.get("n"))
    return eval(str(n) + " * 2")
