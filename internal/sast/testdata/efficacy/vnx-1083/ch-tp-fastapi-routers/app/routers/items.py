import psycopg2
from fastapi import APIRouter

router = APIRouter()


@router.get("/items/{item_id}")
def read_item(item_id: int):
~>    conn = psycopg2.connect(dsn=settings.DATABASE_URL)
    with conn.cursor() as cur:
        cur.execute("SELECT name FROM items WHERE id = %s", (item_id,))
        return {"name": cur.fetchone()[0]}
