from django.http import HttpResponseRedirect


def logout(request):
    response = HttpResponseRedirect("/login")
    response.delete_cookie("role")
    response.delete_cookie("is_admin")
    return response


def remember(request, user):
    response = HttpResponseRedirect("/")
    response.set_signed_cookie("role", user.role, salt="role-cookie", httponly=True)
    return response


def check(request):
    role = request.get_signed_cookie("role", default=None, salt="role-cookie")
    return role == "admin"
