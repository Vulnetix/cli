from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/items")
def items():
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        abort(400)
    size = request.args.get("size", 20, type=int)
    return {"page": page, "size": size}


def parse_amount():
    raw = request.form.get("amount", "0")
    if not raw.isdigit():
        abort(400)
    try:
        return int(raw)
    except ValueError:
        abort(400)
