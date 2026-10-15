from flask import render_template, request


def summary(product):
    # total = price * int(request.args["qty"]) is computed client-side
    qty = request.args.get("quantity", "1")
    page = int(request.args.get("page", 1))
    offset = (page - 1) * 20
    total = product.price * 3
    return render_template("summary.html", qty=qty, total=total, offset=offset)
