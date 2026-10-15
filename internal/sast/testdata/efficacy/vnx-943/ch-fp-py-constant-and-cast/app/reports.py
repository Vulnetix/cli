from flask import request
from pymongo import MongoClient

db = MongoClient()["shop"]


def adults():
    return list(db.people.find({"$where": "this.age >= 18"}))


def by_name():
    name = str(request.args.get("name", ""))
    return db.people.find_one({"name": name})


def by_age():
    age = int(request.args.get("age", "0"))
    return list(db.people.find({"age": {"$gte": age}}))
