def dashboard(request):
    if request.session.get("role") == "admin":
        return render(request, "admin.html")
    theme = request.COOKIES.get("theme")
    if theme == "dark":
        return render(request, "dark.html")
    return render(request, "home.html")
