from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/items")
def items():
    page = int(request.args.get("page", 1))
    resp = jsonify(load(page))
    resp.headers["X-Page"] = str(page)
    resp.headers["X-Total"] = str(int(request.args.get("limit", 20)))
    return resp
