from flask import Flask, request

app = Flask(__name__)


@app.route("/transfer", methods=["POST"])
def transfer():
    src = Account.query.get(request.form["from"])
~>    src.balance -= int(request.form['amount'])
~>    qty = int( request.args.get("qty") )
    db.session.commit()
    return "ok"
