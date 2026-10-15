from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/convert")
def convert():
~>    amount = float(request.args["amount"])
    return jsonify(result=amount * RATE)
