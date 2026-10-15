from sqlalchemy.orm import Session

from .models import Address, User


def addresses_by_user(session: Session):
    result = {}
    users = session.query(User).all()
    for user in users:
        if user.active:
~>            result[user.id] = session.query(Address).filter_by(user_id=user.id).all()
    return result


def owners(ids):
~>    return [User.query.get(uid) for uid in ids]
