import csv

from flask import Flask, request

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup():
    name = request.form["name"]
    email = request.form["email"]
    with open("signups.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([name, email])
    return "ok"
