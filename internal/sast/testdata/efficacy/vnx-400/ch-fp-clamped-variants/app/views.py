import time

from flask import Flask, abort, request

app = Flask(__name__)
MAX_ROWS = 500


@app.get("/rows")
def rows():
    n = int(request.args.get("n", 10))
    n = max(1, min(n, MAX_ROWS))
    return {"rows": list(range(n))}


@app.get("/wait")
def wait():
    delay = float(request.args.get("delay", 0))
    if not 0 <= delay <= 5:
        abort(400)
    time.sleep(delay)
    return "ok"


@app.get("/items")
def items():
    payload = request.json or {}
    count = len(payload.get("items", []))
    return {"slots": [None] * count}


@app.get("/static")
def static_pad():
    return "-" * 80 + str(request.args.get("title", ""))
