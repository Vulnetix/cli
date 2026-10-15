from fastapi import Depends
from sqlalchemy.orm import Session

from svc.db import get_session


class OrderRepository:
    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def by_id(self, order_id: int):
        return self.session.get("Order", order_id)
