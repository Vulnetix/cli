from django.shortcuts import redirect, render


def members(request):
~>    if "logged_in" not in request.COOKIES:
        return redirect("/login")
    return render(request, "members.html")
