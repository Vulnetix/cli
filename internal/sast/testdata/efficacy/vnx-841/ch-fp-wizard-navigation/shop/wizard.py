from flask import render_template, request


def checkout_wizard():
    step = request.args.get("step", "1")
    if step == "2":
        return render_template("checkout/shipping.html")
    if step == "3":
        return render_template("checkout/review.html")
    return render_template("checkout/cart.html")
