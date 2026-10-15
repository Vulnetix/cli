from django.http import HttpResponseRedirect


def logout(request):
    response = HttpResponseRedirect("/")
    response.set_cookie("sessionid", "", max_age=0)
    response.delete_cookie("auth_token")
    response.set_cookie("theme", "dark")
    return response


def expire(request):
    response = HttpResponseRedirect("/")
    response.set_cookie("session_id", None)
    return response
