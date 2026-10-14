from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.clickjacking import xframe_options_exempt


~>@xframe_options_exempt
@login_required
def confirm_payment(request):
    return render(request, "billing/confirm.html", {"invoice": request.GET.get("id")})
