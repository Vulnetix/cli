from django.http import HttpResponseForbidden


def invite(request):
    if request.POST.get('role') == 'admin' and not request.user.is_superuser:
        return HttpResponseForbidden()
    return create_invite(request.POST)
