import os
from flask import Flask, request, send_from_directory

app = Flask(__name__)
REPORTS = "/srv/reports"


@app.get("/report")
def report():
    return send_from_directory(REPORTS, request.args["name"])


@app.get("/invoice")
def invoice():
    n = int(request.args["id"])
    with open(os.path.join(REPORTS, f"invoice-{n}.pdf"), "rb") as fh:
        return fh.read()
