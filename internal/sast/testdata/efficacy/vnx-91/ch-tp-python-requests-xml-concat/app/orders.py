import requests
from flask import Flask, request

app = Flask(__name__)


@app.post("/order")
def order():
~>    body = "<order><qty>" + request.form["qty"] + "</qty></order>"
    r = requests.post(
        "https://erp.internal/orders",
        data=body,
        headers={"Content-Type": "application/xml"},
    )
    return r.text
