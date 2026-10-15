from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/users/{uid}")
async def get_user(uid: int):
    try:
        user = await load(uid)
    except LookupError:
~>        return JSONResponse(content={"error": "user not found"})
    return user
