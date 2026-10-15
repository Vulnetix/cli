import requests
from flask import request

API_BASE = "https://billing.example.com"
session = requests.Session()


def invoice():
    invoice_id = request.args["id"]
    resp = session.get(API_BASE + "/invoices/" + invoice_id, timeout=5)
    return resp.json()
