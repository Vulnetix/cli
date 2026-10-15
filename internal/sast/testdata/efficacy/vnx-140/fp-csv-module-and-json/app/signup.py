import csv
import json

from flask import request


def signup():
    name = request.form["name"]
    email = request.form["email"]
    with open("signups.csv", "a", newline="") as f:
        csv.writer(f).writerow([name, email])
    with open("signups.jsonl", "a") as f:
        f.write(json.dumps({"name": name, "email": email}) + "\n")
    return "ok"


def header_row(f):
    f.write("name,email\n")
    f.write(",".join(["id", "name"]) + "\n")
