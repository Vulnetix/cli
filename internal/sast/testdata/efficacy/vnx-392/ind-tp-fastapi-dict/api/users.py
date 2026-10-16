from fastapi import APIRouter

from .db import get_user_by_email, UserNotFound

router = APIRouter()


@router.get("/users/lookup")
async def lookup_user(email: str):
    try:
        user = await get_user_by_email(email)
    except UserNotFound:
~>        return {"status": "error", "detail": "user not found"}
    return {"id": user.id, "email": user.email}
