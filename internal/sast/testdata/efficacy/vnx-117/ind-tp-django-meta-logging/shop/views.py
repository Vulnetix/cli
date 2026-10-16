import logging

from django.http import HttpResponseRedirect

log = logging.getLogger("shop")


def checkout(request):
    coupon = request.POST.get("coupon")
~>    log.info("checkout with coupon %s", coupon)
~>    log.debug("referer was %s", request.META.get("HTTP_REFERER"))
    return HttpResponseRedirect("/cart/")


def track(request):
~>    log.error("unknown campaign %s" % request.GET["utm_campaign"])
    return HttpResponseRedirect("/")
