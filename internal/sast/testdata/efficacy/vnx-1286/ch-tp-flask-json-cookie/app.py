import json
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.get("/cart")
def cart():
    raw = request.cookies.get("cart", "[]")
~>    items = json.loads(raw)
~>    page = int(request.args.get("page", "1"))
    return jsonify(items=items, page=page)
