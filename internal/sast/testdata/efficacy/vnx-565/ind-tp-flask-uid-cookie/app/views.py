from flask import Blueprint, make_response, redirect, render_template, request

from app.models import Customer

bp = Blueprint("account", __name__)


@bp.route("/orders")
def orders():
~>    customer_id = request.cookies.get("uid")
    customer = Customer.query.filter_by(id=customer_id).first_or_404()
    return render_template("orders.html", orders=customer.orders)


@bp.route("/remember", methods=["POST"])
def remember():
    customer = Customer.query.filter_by(email=request.form["email"]).first_or_404()
    resp = make_response(redirect("/orders"))
~>    resp.set_cookie("user_id", str(customer.id), max_age=86400)
    return resp
