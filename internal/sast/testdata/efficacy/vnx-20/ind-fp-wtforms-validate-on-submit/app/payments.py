from flask import Blueprint, redirect, render_template, request, url_for
from flask_wtf import FlaskForm
from pydantic import BaseModel
from wtforms import DecimalField, StringField
from wtforms.validators import DataRequired

from .ledger import transfer

bp = Blueprint("payments", __name__)


class PaymentForm(FlaskForm):
    payee = StringField("Payee", validators=[DataRequired()])
    amount = DecimalField("Amount")


class Settings(BaseModel):
    region: str


DEFAULTS = {"region": "eu-west-1"}
settings = Settings.model_construct(**DEFAULTS)


@bp.route("/pay", methods=["GET", "POST"])
def pay():
    form = PaymentForm(request.form)
    if form.validate_on_submit():
        transfer(form.payee.data, form.amount.data)
        return redirect(url_for("payments.done"))
    return render_template("pay.html", form=form)
