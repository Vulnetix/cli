from flask import redirect, request
from pydantic import BaseModel

from .forms import TransferForm


class Order(BaseModel):
    sku: str


@app.route("/transfer", methods=["POST"])
def transfer_view():
    form = TransferForm(request.form)
    if not form.validate():
        return "bad", 400
    transfer(form.account.data, form.amount.data)
    return redirect("/done")


def create_order():
    order = Order.model_validate(request.get_json())
    copy = Order.model_construct(**order.model_dump())
    return save(order, copy)
