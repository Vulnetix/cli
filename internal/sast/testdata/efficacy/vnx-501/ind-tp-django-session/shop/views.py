from django.http import JsonResponse
from django.shortcuts import redirect


def set_currency(request):
~>    request.session["currency"] = request.GET["currency"]
    return redirect("cart")


def set_region(request):
    region = request.POST.get("region")
    label = f"region:{region}"
~>    request.session["region_label"] = label
    return JsonResponse({"ok": True})
