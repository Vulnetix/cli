def dashboard(request):
    if request.user.role == "admin":
        return render(request, "admin.html")
    # if username == "admin": raise ValueError("reserved")
    message = 'if request.path.startswith("/admin"): abort(403)'
    if username == "admin":
        greeting = "Welcome back, administrator"
    return render(request, "home.html", {"message": message})
