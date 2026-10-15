from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import User


class UserRepository:
    def __init__(self, session: Session):
        self.session = session

    def get(self, user_id):
        return self.session.execute(select(User).where(User.id == user_id)).scalar_one()

    def emails(self):
        return self.session.execute(text("SELECT email FROM users")).all()
