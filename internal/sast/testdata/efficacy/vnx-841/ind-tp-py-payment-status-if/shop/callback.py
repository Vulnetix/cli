from flask import request

def payment_return(order):
~>    if request.args.get("payment_status") == "success":
        order.status = "paid"
        ship(order)
    return redirect("/done")
