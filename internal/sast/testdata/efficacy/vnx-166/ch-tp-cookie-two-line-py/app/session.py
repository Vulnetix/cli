from flask import request


def user_id():
    cookie = request.cookies.get("sess")
~>    uid = cookie.split(".")[1]
    return uid
