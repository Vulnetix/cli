from django.shortcuts import render


def admin_panel(request):
    name = request.POST.get("name")
    if name:
~>        if request.COOKIES.get('admin') == "1":
            return render(request, "panel.html", {"username": "admin"})
    return render(request, "denied.html")


def settings_view(request):
~>    if request.headers.get("X-Role") == "superuser":
        return render(request, "settings.html", {"all": True})
    if request.GET.get("theme") == "dark":
        return render(request, "settings.html", {"dark": True})
    return render(request, "settings.html")
