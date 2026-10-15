from flask import request


def help_text():
    # never: open(request.args["path"])
    return "do not call open(request.args['path']) directly", request.args.get("q")
