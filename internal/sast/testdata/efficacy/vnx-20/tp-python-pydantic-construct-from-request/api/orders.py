from fastapi import Request
from pydantic import BaseModel


class Order(BaseModel):
    sku: str
    quantity: int


async def create_order(request: Request):
    payload = await request.json()
~>    order = Order.model_construct(**payload)
    return save(order)


def legacy_create(request):
~>    order = Order.construct(**request.get_json())
    return save(order)
