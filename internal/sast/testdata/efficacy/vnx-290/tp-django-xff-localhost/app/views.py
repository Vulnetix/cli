from django.http import HttpResponse, HttpResponseForbidden


def internal_status(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
~>    if ip == '127.0.0.1':
        return HttpResponse(render_status())
    return HttpResponseForbidden()
