from flask import Flask, request, make_response, jsonify

app = Flask(__name__)


@app.route("/api/echo")
def echo():
    resp = make_response(jsonify({"ok": True}))
~>    resp.headers["X-Correlation-Id"] = request.headers.get("X-Correlation-Id", "")
    return resp
