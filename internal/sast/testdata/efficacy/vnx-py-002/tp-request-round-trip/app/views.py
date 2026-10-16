import base64

from flask import Flask, request

app = Flask(__name__)


@app.route("/run", methods=["POST"])
def run():
    values = request.form.getlist("snippet")
    param = values[0] if values else ""
    tmp = base64.b64encode(param.encode("utf-8"))
    bar = base64.b64decode(tmp).decode("utf-8")
~>    exec(bar)
    return "ok"


@app.route("/calc", methods=["POST"])
def calc():
    raw = request.headers.get("X-Expr", "")
    expr = raw.strip()
    restored = base64.b64decode(base64.b64encode(expr.encode()))
~>    return str(eval(restored))
