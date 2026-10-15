from fastapi import APIRouter

from .models import Item, SessionLocal

router = APIRouter()


@router.delete("/admin/items/{item_id}")
async def purge(item_id: int):
    with SessionLocal() as db:
        db.query(Item).filter(Item.id == item_id).delete()
        db.commit()
