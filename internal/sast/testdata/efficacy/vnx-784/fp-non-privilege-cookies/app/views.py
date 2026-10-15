def page(request):
    role = request.COOKIES.get("role", "guest")
    return render(request, "page.html", {"display_role": role})


def consent(request):
    if request.COOKIES.get("cookie_consent") == "yes":
        return enable_analytics(request)
