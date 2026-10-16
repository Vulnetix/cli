from flask import request, abort

def move(src, dst):
    amount = int(request.form["amount"])
    if amount <= 0 or amount > src.balance:
        abort(400)
    src.balance -= amount
    dst.balance += amount
