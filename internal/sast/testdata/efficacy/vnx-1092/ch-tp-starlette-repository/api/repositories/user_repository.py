~>from starlette.requests import Request
from sqlalchemy import select

from api.tables import users


class UserRepository:
    def __init__(self, session):
        self.session = session

    async def current(self, request: Request):
        uid = request.path_params["uid"]
        return await self.session.scalar(select(users).where(users.c.id == uid))
