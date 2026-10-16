from bson import ObjectId
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient()["shop"]


@app.route("/user")
def user():
    name = request.args.get("name", "")
    doc = db.users.find_one({"username": name})
    return jsonify(str(doc))


@app.post("/login")
def login():
    body = request.get_json()
    doc = db.users.find_one({"username": str(body["username"]), "pw": {"$eq": str(body["password"])}})
    return jsonify(bool(doc))


@app.get("/item/<item_id>")
def item(item_id):
    return jsonify(str(db.items.find_one({"_id": ObjectId(item_id)})))


@app.get("/stale")
def stale():
    return jsonify(list(db.items.find({"$where": "this.stock < this.reorderLevel"})))


@app.get("/page")
def page():
    n = int(request.args.get("n", "10"))
    return jsonify(list(db.items.find({"$where": "this.stock < 5"}).limit(n)))
