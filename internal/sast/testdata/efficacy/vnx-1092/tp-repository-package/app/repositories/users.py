~>from fastapi import Request, Depends
from sqlalchemy.orm import Session


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    async def current(self, req: Request):
        uid = req.path_params["uid"]
        return self.db.get("User", uid)
