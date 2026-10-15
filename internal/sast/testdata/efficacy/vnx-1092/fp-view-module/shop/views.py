from flask import request, render_template, redirect

from .models import Order


def create():
    note = request.form.get("note", "")
    Order.create(note=note)
    return redirect("/orders")
