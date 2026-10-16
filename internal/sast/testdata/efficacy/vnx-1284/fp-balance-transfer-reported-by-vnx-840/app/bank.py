from flask import Flask, request

app = Flask(__name__)


@app.route("/transfer", methods=["POST"])
def transfer():
    src = Account.query.get(request.form["from"])
    dst = Account.query.get(request.form["to"])
    dst.balance += int(request.form["amount"])
    src.balance -= int(request.form['amount'])
    db.session.commit()
    return {"ok": True}
