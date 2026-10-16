from flask import request

def move(src, dst):
    amount = int(request.form["amount"])
~>    src.balance -= amount
    dst.balance += 1
    db.session.commit()
