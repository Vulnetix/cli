from flask import Flask, abort, request

app = Flask(__name__)
MAX_ITEMS = 500


@app.route("/items")
def items():
    n = int(request.args.get("n", 10))
    if n < 0 or n > MAX_ITEMS:
        abort(400)
    return {"items": [i for i in range(n)]}
