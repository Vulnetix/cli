from fastapi import APIRouter, Cookie, Header, HTTPException

router = APIRouter()


@router.delete("/users/{user_id}")
def delete_user(user_id: int, x_role: str = Header(default="user")):
~>    if x_role != "admin":
        raise HTTPException(status_code=403)
    return {"deleted": user_id}


@router.get("/reports")
def reports(is_staff: str | None = Cookie(default=None)):
~>    if is_staff == "1":
        return {"reports": ["all"]}
    return {"reports": []}
