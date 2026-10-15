from datetime import datetime

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/report")
def report():
    try:
~>        days = int(request.args["days"])
    except KeyError:
        days = 7
~>    since = datetime.strptime(request.args.get("since"), "%Y-%m-%d")
    return jsonify(build(days, since))


@app.route("/basket", methods=["POST"])
def basket():
    raw = request.form.get("qty")
~>    qty = float(raw)
    return jsonify(add(qty))
