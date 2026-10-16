import json
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_rows():
~>    rows = json.loads(request.data)
    total = 0
    for row in rows:
        total += len(row)
    return jsonify({"rows": total})
