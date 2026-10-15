from flask import request


def ext():
    name = request.args.get("file", "")
    suffix = name.split(".")[-1]
    first = request.args["host"].split(":")[0]
    return suffix + first
