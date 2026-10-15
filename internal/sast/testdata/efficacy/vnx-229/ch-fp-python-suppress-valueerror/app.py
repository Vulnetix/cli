from contextlib import suppress

from flask import Flask, request

app = Flask(__name__)


@app.route("/items")
def items():
    limit = 20
    with suppress(ValueError, TypeError):
        limit = int(request.args.get("limit", "20"))
    return {"items": ITEMS[:limit]}
