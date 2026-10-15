from fastapi import APIRouter
from app.db import engine, Base

router = APIRouter()


~>@router.post("/admin/reset-db")
async def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return {"status": "reset"}
