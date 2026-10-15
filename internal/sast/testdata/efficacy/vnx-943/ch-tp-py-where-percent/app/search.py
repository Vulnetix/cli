from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient()["shop"]


@app.route("/search")
def search():
    name = request.args.get("name", "")
~>    cursor = db.products.find({"$where": "this.name == '%s'" % name})
    return {"items": [str(p["_id"]) for p in cursor]}


@app.route("/by-owner")
def by_owner():
    owner = request.args["owner"]
~>    rows = db.products.find({"$where": "this.owner == '{}'".format(owner)})
    return {"count": len(list(rows))}
