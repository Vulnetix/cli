from django.http import HttpResponseForbidden
from django.shortcuts import render


def staff_dashboard(request):
    if request.user.is_staff:
        return render(request, "staff/dashboard.html")
    is_admin = request.user.is_superuser
    if not is_admin:
        return HttpResponseForbidden()
    return render(request, "staff/limited.html")
