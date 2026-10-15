from flask import request


@bp.route("/transfer", methods=["POST"])
def transfer():
    src = Account.query.get(request.form["from_account"])
    dst = Account.query.get(request.form["to_account"])
    amount = int(request.form["amount"])
~>    src.balance -= amount
~>    dst.balance += int(request.form["amount"])
    db.session.commit()
    return {"ok": True}
