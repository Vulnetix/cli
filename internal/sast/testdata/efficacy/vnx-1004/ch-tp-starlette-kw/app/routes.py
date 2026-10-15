from starlette.responses import JSONResponse


async def login(request):
    token = await issue(request)
    response = JSONResponse({"ok": True})
~>    response.set_cookie(key="access_token", value=token, secure=True)
    return response


async def legacy(request):
    response = JSONResponse({"ok": True})
~>    response.set_cookie("sessionid", "x", httponly=False)
    return response
