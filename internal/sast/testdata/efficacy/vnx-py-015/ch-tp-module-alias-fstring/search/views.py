import re as regexp

from flask import Flask, request

app = Flask(__name__)


@app.route("/grep")
def grep():
    prefix = request.args.get("prefix", "")
~>    hits = [l for l in open("/var/log/app.log") if regexp.match(f"^{prefix}.*", l)]
    return {"count": len(hits)}
