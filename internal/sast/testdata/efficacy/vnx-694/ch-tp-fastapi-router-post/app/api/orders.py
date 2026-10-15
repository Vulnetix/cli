from fastapi import APIRouter

router = APIRouter()


@router.post('/orders')
async def create_order(payload: dict):
    return {"ok": True}


@router.get('/orders/{order_id}')
async def get_order(order_id: int):
    return {"id": order_id}


~>@router.post("/orders")
async def create_order_legacy(payload: dict):
    return {"ok": False}
