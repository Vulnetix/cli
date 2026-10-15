from fastapi import APIRouter, Depends
from app.security import get_current_admin

router = APIRouter(prefix="/api", dependencies=[Depends(get_current_admin)])


@router.delete("/admin/users/{user_id}")
async def delete_user(user_id: int):
    return {"deleted": user_id}
