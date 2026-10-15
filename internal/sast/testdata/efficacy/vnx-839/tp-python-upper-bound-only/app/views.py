from flask import request


@app.route("/item")
def item():
    idx = int(request.args.get("i", "0"))
~>    if idx < len(ITEMS):
        return ITEMS[idx]
    return "not found", 404


@app.route("/slot", methods=["POST"])
def slot():
    pos = int(request.form["pos"])
~>    if pos >= MAX_SLOTS:
        abort(400)
    slots[pos] = request.form["value"]
