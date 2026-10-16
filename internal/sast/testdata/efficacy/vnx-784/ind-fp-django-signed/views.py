def dashboard(request):
    if request.get_signed_cookie("admin", default=None, salt="roles") == "1":
        return HttpResponse("admin")
    return HttpResponse(status=403)
