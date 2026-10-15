def login(request):
    response = redirect("/")
~>    response.set_cookie("session_id", token)
~>    response.set_cookie(key="auth_cookie", value=cookie, max_age=3600)
    return response
