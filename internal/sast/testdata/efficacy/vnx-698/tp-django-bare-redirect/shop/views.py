from django.http import HttpResponseRedirect
from django.shortcuts import redirect, render


def dashboard(request):
    if not request.user.is_authenticated:
~>        redirect("login")
    return render(request, "dashboard.html", {"orders": request.user.orders.all()})


def refund(request, pk):
    if not request.user.is_staff:
~>        HttpResponseRedirect("/")
    Order.objects.get(pk=pk).refund()
    return redirect("orders")
