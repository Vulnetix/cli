from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import cache_page
from django.shortcuts import render


@login_required
~>@cache_page(60 * 15)
def dashboard(request):
    return render(request, "dashboard.html", {"orders": request.user.orders.all()})
