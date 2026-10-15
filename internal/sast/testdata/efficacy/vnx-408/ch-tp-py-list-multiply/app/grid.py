from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/grid")
def grid():
    width = int(request.args.get("w", "8"))
~>    row = [0] * width
    return jsonify(row)
