import logging

from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie

log = logging.getLogger(__name__)

WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = None


def warn_exempt(view):
    log.warning("view %s uses csrf_exempt; review it", view.__name__)
    return view


@csrf_protect
def transfer(request):
    return render(request, "transfer.html")


@ensure_csrf_cookie
def page(request):
    return render(request, "page.html")


def is_csrf_exempt(view):
    return getattr(view, "csrf_exempt", False)
