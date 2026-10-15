import re

from flask import Flask, request

app = Flask(__name__)


@app.route("/find")
def find():
    term = re.escape(request.args.get("term", ""))
    rx = re.compile(term, re.I)
    literal = request.args.get("lit", "")
    safe = re.compile(r"\b" + re.escape(literal) + r"\b")
    return {"a": bool(rx.search("abc")), "b": bool(safe.search("abc"))}
