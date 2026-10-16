from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient("mongodb://localhost:27017")["shop"]


@app.route("/orders")
def list_orders():
    owner = request.args.get("owner", "")
    limit = 20
~>    cursor = db.orders.find({"$where": f"this.owner == '{owner}'"}).limit(limit)
    return jsonify([str(o["_id"]) for o in cursor])
