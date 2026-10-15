from fastapi import APIRouter
from sqlalchemy import select

from app.db import SessionLocal
from app.models import User

router = APIRouter()


@router.get("/users/{uid}")
def get_user(uid: int):
    with SessionLocal() as session:
        stmt = select(User).where(User.id == uid)
        user = session.execute(stmt).scalar_one()
        return {"id": user.id}
