from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from .auth import get_current_admin
from .database import get_db
from .models import Item, User

app = FastAPI()


@app.delete("/items/{item_id}", status_code=204)
async def delete_item(
    item_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    db.query(Item).filter(Item.id == item_id).delete()
    db.commit()


@app.delete("/admin/cache", dependencies=[Depends(get_current_admin)])
async def clear_cache(db: Session = Depends(get_db)):
    db.query(Item).filter(Item.cached.is_(True)).delete()
