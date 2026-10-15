from fastapi import APIRouter

router = APIRouter(prefix="/v1")


~>@router.post("/backoffice/refunds/{order_id}")
async def refund(order_id: int):
    await issue_refund(order_id)
    return {"refunded": order_id}
