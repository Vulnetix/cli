import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/services/restart")
def restart():
    unit = request.json["unit"]
~>    subprocess.check_call(["sudo", "-n", "/usr/bin/systemctl", "restart", unit])
    return {"ok": True}
