import os
from flask import Flask, request, jsonify

app = Flask(__name__)
os.environ["FLASK_ENV"] = "production"
os.environ.setdefault("TZ", "UTC")


@app.get("/feature")
def feature():
    name = request.args.get("name", "")
    enabled = os.environ.get("FEATURE_" + name.upper(), "0") == "1"
    return jsonify(enabled=enabled)
