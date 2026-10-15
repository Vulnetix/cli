class UserService:
    def __init__(self, db):
        self.db = db

    def getUser(self, uid):
        return self.db.get(uid)

~>    async def get_user(self, uid):
        row = await self.db.fetch(uid)
        if row and row.active:
            return row
        return None
