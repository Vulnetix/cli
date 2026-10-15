class ItemRepository:
    def __init__(self, conn):
        self.conn = conn

    async def get(self, item_id):
        return await self.conn.fetchrow("SELECT id, name FROM items WHERE id = $1", item_id)
