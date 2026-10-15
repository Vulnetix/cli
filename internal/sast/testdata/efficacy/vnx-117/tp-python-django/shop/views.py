import logging

from django.http import JsonResponse

log = logging.getLogger("shop")


def checkout(request):
    coupon = request.POST.get("coupon", "")
    note = "coupon=" + coupon
~>    log.info(note)
~>    log.debug("search: %s" % request.GET["q"])
    return JsonResponse({"ok": True})
