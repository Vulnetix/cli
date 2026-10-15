import requests
from flask import Flask, request

CATALOG_API = "https://catalog.internal.example.com"

app = Flask(__name__)


@app.route("/items")
def item():
    item_id = request.args.get("id", "")
    r = requests.get(f"{CATALOG_API}/items/{int(item_id)}", timeout=3)
    return r.json()
