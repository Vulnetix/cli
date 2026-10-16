from fastapi import APIRouter

router = APIRouter()


@router.post("/orders/{oid}/cancel")
async def cancel(oid: int, db):
    query = "UPDATE orders SET status = 'cancelled' WHERE id = :oid"
~>    await db.execute(query, {"oid": oid})
    return {"ok": True}
