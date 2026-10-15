from starlette.responses import RedirectResponse


async def login(request):
    form = await request.form()
    user = await authenticate(form["username"], form["password"])
    response = RedirectResponse("/", status_code=303)
~>    response.set_cookie(key="access_level", value=str(user.level), httponly=True)
    return response


async def dashboard(request):
~>    if request.cookies.get('is_admin') == "1":
        return admin_view(request)
    return user_view(request)
