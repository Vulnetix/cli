from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .db import get_db
from .models import Item

router = APIRouter(prefix="/items")


@router.delete("/{item_id}")
~>def delete_item(item_id: int, db: Session = Depends(get_db)):
    db.query(Item).filter(Item.id == item_id).delete()
    db.commit()
    return {"deleted": item_id}
