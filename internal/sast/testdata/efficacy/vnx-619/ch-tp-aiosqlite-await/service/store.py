import aiosqlite


async def count_orders(db: aiosqlite.Connection) -> int:
~>    cursor = await db.cursor()
    await cursor.execute("SELECT COUNT(*) FROM orders")
    (n,) = await cursor.fetchone()
    return n
