from django.conf import settings
from django.shortcuts import redirect


def office_login(request):
    ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0]
~>    if ip in settings.OFFICE_IPS:
        request.session['is_admin'] = True
        return redirect('/admin/')
    return redirect('/login/')
