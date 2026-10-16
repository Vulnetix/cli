import re
from flask import Flask, request

app = Flask(__name__)


@app.route("/s")
def s():
~>    pattern = re.compile(request.args.get("q"))
    return str(bool(pattern.search("text")))
