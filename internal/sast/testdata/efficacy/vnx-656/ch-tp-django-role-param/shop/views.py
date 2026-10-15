from django.http import HttpResponse


def dashboard(request):
~>    if request.GET.get('role') == 'admin':
        return HttpResponse(render_admin())
    return HttpResponse(render_user())
