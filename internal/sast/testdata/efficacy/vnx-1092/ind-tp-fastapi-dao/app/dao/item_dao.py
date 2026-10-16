~>from fastapi import Request
from sqlalchemy.orm import Session


class ItemDao:
    def __init__(self, db: Session):
        self.db = db

    def create(self, req: Request):
~>        body = req.json
        return body
