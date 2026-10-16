from flask import Flask, request

app = Flask(__name__)


@app.route("/find")
def find():
    q = request.args.get("q", "").strip()
    name = request.form["name"].lower()
    agent = request.headers.get("User-Agent", "").lower()
    return {"q": q, "name": name, "agent": agent}
