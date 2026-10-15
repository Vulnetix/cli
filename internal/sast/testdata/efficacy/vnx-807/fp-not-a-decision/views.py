def login(request):
    response = HttpResponse("ok")
    response.set_cookie("admin", "0", max_age=200)
    theme = request.COOKIES.get("theme")
    if theme == "dark":
        response["X-Theme"] = "dark"
    return response
