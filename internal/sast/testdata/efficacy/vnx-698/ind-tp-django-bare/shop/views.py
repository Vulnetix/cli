from django.http import HttpResponseRedirect


def delete_account(request):
    if not request.user.is_authenticated:
~>        HttpResponseRedirect("/accounts/login/")
    request.user.delete()
    return HttpResponseRedirect("/")
