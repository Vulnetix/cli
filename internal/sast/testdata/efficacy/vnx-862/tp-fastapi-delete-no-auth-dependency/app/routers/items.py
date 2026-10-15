from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Item

router = APIRouter()


@router.delete("/items/{item_id}", status_code=204)
~>async def delete_item(item_id: int, db: Session = Depends(get_db)):
    db.query(Item).filter(Item.id == item_id).delete()
    db.commit()


@router.get("/items/{item_id}")
async def read_item(item_id: int, db: Session = Depends(get_db)):
    return db.query(Item).get(item_id)
