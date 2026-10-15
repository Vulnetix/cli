from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/items")
def items():
    limit = request.args.get("limit", "20")
~>    rows = db.fetch(limit=int(limit))
    return jsonify(rows)
