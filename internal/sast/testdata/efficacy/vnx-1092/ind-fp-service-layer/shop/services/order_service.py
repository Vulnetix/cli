from flask import request, redirect, flash

from shop.models import Order


def place_order():
    note = request.form.get("note", "")
    order = Order.create(note=note)
    flash("placed")
    return redirect("/orders/%d" % order.id)
