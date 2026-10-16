from django.shortcuts import render


def panel(request):
    # A decision on a privilege cookie: VNX-784 reports it.
    if request.COOKIES.get("is_admin") == "true":
        return render(request, "panel/admin.html")
    return render(request, "panel/user.html")
