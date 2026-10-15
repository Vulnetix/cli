from flask import Flask, request

app = Flask(__name__)


@app.route("/transfer", methods=["POST"])
def transfer():
~>    assert request.form["amount"].isdigit()
~>    assert int(request.args.get("limit", 0)) <= 100, "limit too high"
~>    assert request.json.get("account") in allowed_accounts()
    return do_transfer(request.form["amount"])
