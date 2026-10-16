from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    return str(eval(request.args.get("q", "0")))


class Formula:
    def apply(self, row):
~>        return eval(row["formula"], {"__builtins__": None}, row)
