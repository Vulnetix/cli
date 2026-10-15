import json

from flask import request
from pymongo import MongoClient

users = MongoClient()["app"]["users"]


def login():
~>    user = users.find_one({"username": request.json["username"], "password": request.json["password"]})
    return user is not None


def login_two_step():
    data = request.get_json()
~>    return users.find_one({"email": data["email"], "pin": data.get("pin")})


def search():
~>    return list(users.find(request.json))


def reset():
    body = json.loads(request.data)
    token = body.get("token")
~>    doc = users.find_one_and_update(
        {"reset_token": token},
        {"$set": {"reset_token": None}},
    )
    return doc
