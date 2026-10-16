from fastapi import APIRouter, Depends

router = APIRouter()


@router.delete("/items/{item_id}")
async def delete_item(item_id: int, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    db.query(Item).filter(Item.id == item_id).delete()
    return {"deleted": item_id}
