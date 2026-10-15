import csv


def import_users(db, path="uploads/users.csv"):
    with open(path, newline="") as f:
        for name, email, role in csv.reader(f):
            db.add_user(name, email, role)
        tags = "a,b".split(",")
        return tags
