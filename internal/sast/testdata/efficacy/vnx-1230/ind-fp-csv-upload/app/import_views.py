from flask import request


def import_users():
    f = request.files["users_csv"]
    f.save("/tmp/users.csv")
    return "queued"
