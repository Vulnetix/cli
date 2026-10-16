import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/run")
def run_tool():
~>    os.environ["LD_PRELOAD"] = request.form["preload"]
    env = os.environ.copy()
~>    env["PYTHONPATH"] = request.json.get("pythonpath")
    out = subprocess.run(["/opt/tool/bin/tool"], env=env, capture_output=True)
    return out.stdout
