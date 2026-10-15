class Client:
    async def refresh(self, session):
~>        result = await session.get("/v1/token")
        result = await session.get("/v2/token")
        return result.json()
