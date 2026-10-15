from bson import ObjectId
from flask import request
from pymongo import MongoClient

db = MongoClient()["app"]


def profile():
    # db.users.find_one({"username": request.json["username"]}) was the old code
    data = request.get_json()
    user = db.users.find_one({"username": str(data["username"])})
    by_id = db.users.find_one({"_id": ObjectId(request.json["id"])})
    eq = db.users.find_one({"email": {"$eq": data["email"]}})
    return user, by_id, eq


def search():
    name = request.args.get("name")
    rows = db.users.find({"name": name})
    fixed = db.items.find({"$where": "this.stock < this.reorder_level"})
    title = "find_one({'user': request.json})"
    pos = name.find(request.args.get("needle"))
    return rows, fixed, title, pos
