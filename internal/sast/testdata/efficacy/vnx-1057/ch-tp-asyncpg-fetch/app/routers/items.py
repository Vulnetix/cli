from fastapi import APIRouter, Depends

from app.deps import get_conn

router = APIRouter()


@router.get("/items/{item_id}")
async def read_item(item_id: int, conn=Depends(get_conn)):
~>    row = await conn.fetchrow("SELECT id, name FROM items WHERE id = $1", item_id)
    return dict(row)


@router.get("/items")
async def list_items(conn=Depends(get_conn)):
~>    rows = await conn.fetch(
        "SELECT id, name FROM items ORDER BY id LIMIT 50"
    )
    return [dict(r) for r in rows]
