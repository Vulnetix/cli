def admin_panel(request):
    if request.user.is_staff:
        return render(request, "admin.html")
    if request.session.get("role") == "admin":
        return render(request, "admin.html")
    return HttpResponse(status=403)
