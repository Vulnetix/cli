from django.shortcuts import redirect, render


def settings_page(request):
    # A decision on a privilege cookie: VNX-784 reports it.
    if request.COOKIES.get("role") == "admin":
        return render(request, "settings/all.html")
    return redirect("home")
