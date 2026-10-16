from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)
TREE = etree.parse("data/staff.xml")


@app.route("/staff/login", methods=["POST"])
def staff_login():
    user = request.form.get("user", "")
    pw = request.form.get("password", "")
~>    matches = TREE.xpath(f"//staff[@login='{user}' and @password='{pw}']")
    return jsonify({"ok": bool(matches)})
