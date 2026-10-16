from flask import Flask, request

app = Flask(__name__)


@app.after_request
def add_cors(resp):
    origin = request.headers.get("Origin", "")
~>    if origin.endswith("acme.com"):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp
