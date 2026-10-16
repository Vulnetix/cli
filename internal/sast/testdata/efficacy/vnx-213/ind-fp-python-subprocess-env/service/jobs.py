import os
import subprocess

from flask import Flask, jsonify

app = Flask(__name__)


@app.post("/jobs/reindex")
def reindex():
    env = os.environ.copy()
    env["REINDEX_BATCH"] = "500"
    subprocess.run(["./bin/reindex"], env=env, check=True)
    return jsonify(status="started", region=os.environ.get("AWS_REGION"))
