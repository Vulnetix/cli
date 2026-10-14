import re

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/filter")
def filter_items():
~>    rx = re.compile(request.args.get("pattern", ".*"))
    pattern = request.args["q"]
~>    hits = [i for i in ITEMS if re.search(pattern, i.name)]
    expr = request.form.get("expr")
~>    exact = re.match(f"^{expr}$", request.args.get("v", ""))
    term = request.values.get("t")
    rule = "(" + term + ")+"
~>    parts = re.split(rule, TEXT)
    return jsonify(rx.pattern, hits, bool(exact), parts)


@app.route("/grep/<pat>")
def grep(pat):
~>    return jsonify(re.findall(pat, LOG_TEXT))
