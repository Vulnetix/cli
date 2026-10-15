from fastapi import APIRouter, Response

router = APIRouter()


@router.post("/login")
def login(response: Response, token: str):
~>    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        samesite="lax",
    )
    return {"ok": True}
