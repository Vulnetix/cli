from flask import Flask, request

app = Flask(__name__)


@app.route("/fill")
def fill():
    total = int(request.args["total"])
    i = 0
    out = []
~>    while i < total:
        out.append(i)
        i += 1
    return {"n": len(out)}
