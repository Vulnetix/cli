from fastapi import Response


def login(response: Response, user):
    token = issue_token(user)
~>    response.set_cookie(
        "access_token",
        token,
        secure=True,
        samesite="lax",
    )
    return {"ok": True}
