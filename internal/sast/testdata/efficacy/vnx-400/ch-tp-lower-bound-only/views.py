from flask import Flask, abort, request

app = Flask(__name__)


@app.get("/repeat")
def repeat():
    n = request.args.get("n", type=int)
    if n is None or n <= 0:
        abort(400)
~>    return "ab" * n


@app.get("/wait")
def wait():
    secs = request.args.get("s", type=float)
    if secs < 0:
        abort(400)
~>    time.sleep(secs)
    return "done"


@app.get("/rows")
def rows():
    n = request.args.get("n", type=int)
    if n < 1 or n > 500:
        abort(400)
    return {"rows": [0] * n}
