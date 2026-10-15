from fastapi import APIRouter

from app.db import database

router = APIRouter()


@router.get("/items/{item_id}")
async def read_item(item_id: int):
~>    row = await database.fetch_one("SELECT * FROM items WHERE id = :id", {"id": item_id})
    return dict(row)


@router.get("/items")
async def list_items():
    return await database.fetch_all("SELECT * FROM items")
