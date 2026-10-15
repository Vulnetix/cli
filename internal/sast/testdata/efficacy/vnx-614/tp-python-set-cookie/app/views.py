from django.http import HttpResponse


def login(request):
    token = issue_token(request.user)
    response = HttpResponse("ok")
~>    response.set_cookie("auth_token", token, httponly=True)
~>    response.set_cookie(key="sessionid", value=request.session.session_key)
~>    response.set_cookie("theme", "dark", secure=False)
~>    response.set_cookie(
        "refresh_token",
        token,
        httponly=True,
        samesite="Strict",
    )
    return response
