from flask import request

# qty = int(request.form["quantity"])  -- old version crashed on empty input
HELP = "int(request.args['page']) raises ValueError on bad input"


def help_text():
    return HELP
