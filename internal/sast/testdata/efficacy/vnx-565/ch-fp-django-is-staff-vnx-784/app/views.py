from django.http import HttpResponseForbidden
from django.shortcuts import render


def dashboard(request):
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    if request.COOKIES.get('is_staff') == 'True':
        return render(request, "staff.html")
    return HttpResponseForbidden()
