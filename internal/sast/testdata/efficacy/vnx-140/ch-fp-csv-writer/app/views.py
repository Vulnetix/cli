import csv
from flask import request


def subscribe():
    with open("subscribers.csv", "a", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([request.form["name"], request.form["email"]])
    return "ok"
