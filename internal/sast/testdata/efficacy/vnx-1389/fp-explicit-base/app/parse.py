from flask import request


def mode():
    a = int(request.args.get("mode"))
    b = int(request.args.get("mask"), 16)
    c = int(request.args.get("n"), 10)
    d = int("0x1f", 0)
    e = int(value, base=2)
    return a, b, c, d, e
