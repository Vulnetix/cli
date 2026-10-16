from flask import request

DEFAULTS = {"sort": "created", "order": "desc"}


@app.route("/search")
def search():
~>    params = {**DEFAULTS, **request.args.to_dict()}
    return run_search(params)
