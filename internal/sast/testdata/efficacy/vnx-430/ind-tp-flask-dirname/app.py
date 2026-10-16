import os

from flask import Flask, jsonify

~>app = Flask(__name__, static_folder=os.path.dirname(__file__), static_url_path="")


@app.get("/api/health")
def health():
    return jsonify(status="ok")
