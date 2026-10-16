from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))
