from flask import request


def page():
    n = request.args.get("n", type=int)
    if n == 0:
        return "first"
    choice = input("pick: ")
    if choice == "1":
        return "one"
    return "other"
