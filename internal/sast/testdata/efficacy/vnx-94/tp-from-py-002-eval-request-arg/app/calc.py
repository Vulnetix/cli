from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
~>    result = eval(request.args.get("expr", "0"))
    return {"result": result}
