from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/prefetch")
def prefetch():
    resp = make_response("")
~>    resp.headers.add("Link", request.args.get("link"))
    return resp
