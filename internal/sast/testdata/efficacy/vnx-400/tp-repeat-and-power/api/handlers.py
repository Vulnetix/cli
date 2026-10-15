from flask import request


def banner():
    width = int(request.args.get("width"))
~>    return "=" * width


def power():
    exp = int(request.form["exp"])
~>    return str(10 ** exp)


def pad():
    times = request.values.get("times", type=int)
~>    return ["-"] * times
