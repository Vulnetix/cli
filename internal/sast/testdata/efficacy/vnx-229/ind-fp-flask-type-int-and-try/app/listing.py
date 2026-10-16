from flask import request, abort


@app.route("/items")
def items():
    page = request.args.get("page", 1, type=int)
    try:
        per_page = int(request.args["per_page"])
    except (KeyError, TypeError, ValueError):
        abort(400)
    return render(page, per_page)
