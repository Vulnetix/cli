from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient()["shop"]


@app.route("/orders")
def orders():
    owner = request.args.get("owner", "")
~>    cursor = db.orders.find({"$where": f"this.owner == '{owner}'"})
    return {"orders": list(cursor)}


@app.route("/stock")
def stock():
    level = request.args.get("level")
~>    rows = db.items.find({"$where": "this.stock < " + level})
~>    more = db.items.find({'$where': "this.qty > %s" % level})
    return {"rows": list(rows), "more": list(more)}
