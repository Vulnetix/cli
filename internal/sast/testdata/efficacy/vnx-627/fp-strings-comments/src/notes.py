from flask import request

# never do: globals()[request.args["name"]] = 1
HELP = "globals()[request.args['name']] is dangerous"


def view():
    return HELP + request.args.get("q", "")
