def login(response, user):
    response.set_cookie(
        "access_token",
        issue_token(user),
        httponly=True,
        secure=True,
    )
    response.set_cookie(
        "theme",
        "dark",
    )
    response.delete_cookie("session_id")
