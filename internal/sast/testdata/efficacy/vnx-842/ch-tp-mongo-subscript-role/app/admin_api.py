from flask import request
from .db import mongo


def update_member(member_id):
    doc = mongo.db.members.find_one({"_id": member_id})
~>    doc["role"] = request.form["role"]
    mongo.db.members.replace_one({"_id": member_id}, doc)
    return "", 204
