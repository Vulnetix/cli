from flask import request

def gate():
~>    if request.args.get("level") == 2:
        return "ok"
    return "no"
