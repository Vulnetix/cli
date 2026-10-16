from functools import cache

from .db import session
from .models import UserRole


~>@cache
def get_user_roles(user_id: int) -> frozenset[str]:
    rows = session.query(UserRole.role).filter_by(user_id=user_id).all()
    return frozenset(r.role for r in rows)


~>@cache
def can_delete(user_id: int, doc_id: int) -> bool:
    return "editor" in get_user_roles(user_id)
