from fastapi import APIRouter, Response

router = APIRouter()


@router.post("/login")
def login(response: Response, token: str):
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
~>        samesite="none",
        secure=True,
    )
    return {"ok": True}
