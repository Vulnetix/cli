from fastapi import APIRouter, HTTPException

router = APIRouter()


~>@router.post("/token")
async def issue_token(form: LoginForm):
    user = await authenticate(form.username, form.password)
    if not user:
        raise HTTPException(status_code=401)
    return {"access_token": make_jwt(user)}
