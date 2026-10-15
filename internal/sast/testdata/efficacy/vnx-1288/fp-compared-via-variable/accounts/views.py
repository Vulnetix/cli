from django.shortcuts import render


def signup(request):
    p1 = request.POST.get("password1")
    p2 = request.POST.get("password2")
    if p1 and p1 == p2:
        return create(request)
    return render(request, "signup.html", {"error": "Passwords differ"})
