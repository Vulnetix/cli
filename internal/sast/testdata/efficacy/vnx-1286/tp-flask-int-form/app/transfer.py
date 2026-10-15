from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/transfer", methods=["POST"])
def transfer():
    src = request.form["from_acc"]
~>    amount = int(request.form["amount"])
~>    rate = float(request.args.get("rate", "1.0"))
    return jsonify(src=src, amount=amount * rate)
