from flask import Blueprint, redirect, render_template, request, url_for
from flask_wtf import FlaskForm
from wtforms import DecimalField, StringField
from wtforms.validators import DataRequired, NumberRange

from .ledger import transfer

bp = Blueprint("payments", __name__)


class PaymentForm(FlaskForm):
    payee = StringField("Payee", validators=[DataRequired()])
    amount = DecimalField("Amount", validators=[NumberRange(min=0.01)])


@bp.route("/pay", methods=["POST"])
def pay():
~>    form = PaymentForm(request.form)
    transfer(form.payee.data, form.amount.data)
    return redirect(url_for("payments.done"))
