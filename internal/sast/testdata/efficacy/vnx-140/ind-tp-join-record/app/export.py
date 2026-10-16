from django.http import JsonResponse


def record_order(request):
    item = request.POST.get("item", "")
    qty = request.POST.get("qty", "0")
    line = "|".join([item, qty, request.META.get("REMOTE_ADDR", "")])
    with open("/var/log/orders.psv", "a", encoding="utf-8") as fh:
~>        fh.write(line + "\n")
    return JsonResponse({"ok": True})
