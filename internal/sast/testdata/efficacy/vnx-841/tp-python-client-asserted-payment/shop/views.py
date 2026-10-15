from flask import request, redirect


@app.route("/payment/return")
def payment_return():
    order = Order.query.get(request.args["order_id"])
~>    if request.args.get("payment_status") == "success":
        order.status = "paid"
        db.session.commit()
    return redirect("/orders")


@app.post("/orders/<oid>/mark")
def mark(oid):
    order = Order.query.get(oid)
~>    order.is_paid = request.form.get("is_paid") == "1"
    approved = request.json["approved"]
~>    order.approved = approved
    db.session.commit()
