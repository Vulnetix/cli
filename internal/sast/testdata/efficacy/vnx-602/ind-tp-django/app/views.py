from django.http import HttpResponseForbidden


def danger(request):
~>    if request.POST.get('is_admin') == "1":
        return run(request)
    return HttpResponseForbidden()
