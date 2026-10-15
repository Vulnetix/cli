from flask import request
from pydantic import BaseModel, PositiveInt


class OrderLine(BaseModel):
    quantity: PositiveInt


def place(product):
    line = OrderLine(quantity=request.json["quantity"])
    qty = request.json["quantity"]
    OrderLine(quantity=qty)
    product.stock -= qty
    return product
