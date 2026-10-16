import os
import platform

from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/status")
def status():
    return jsonify(
        status="ok",
        python=platform.python_version(),
~>        environment=dict(os.environ),
    )
