from django.http import HttpResponseRedirect


def after_login(request):
    next_url = request.GET.get("next")
~>    return HttpResponseRedirect(next_url)
