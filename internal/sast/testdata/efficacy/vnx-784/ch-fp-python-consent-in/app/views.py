def page(request):
    if "cookie_consent" in request.COOKIES:
        banner = False
    if "sessionid" not in request.COOKIES:
        return None
    return banner
