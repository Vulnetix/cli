from django.http import HttpResponseForbidden
from django.shortcuts import render


def dashboard(request):
~>    if request.COOKIES.get('is_staff') == 'True':
        return render(request, "staff.html")
    return HttpResponseForbidden()
