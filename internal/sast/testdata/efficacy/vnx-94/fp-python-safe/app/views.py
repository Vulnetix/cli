import ast
import re

from flask import Flask, request

app = Flask(__name__)
pattern = re.compile(r"\d+")


@app.route("/parse")
def parse():
    value = ast.literal_eval(request.args["v"])
    total = eval("2 + 2")
    # eval(request.args["v"]) is never safe
    model.eval()
    score = evaluate(request.args.get("q"))
    n = eval(str(int(request.args["n"])))
    note = "do not exec(request.form['code'])"
    return str((value, total, score, n, note))
