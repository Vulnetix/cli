from django.shortcuts import render


def legacy_admin(request):
    if request.COOKIES.get("admin") == "1":
        return render(request, "legacy/admin.html")
    return render(request, "legacy/home.html")
