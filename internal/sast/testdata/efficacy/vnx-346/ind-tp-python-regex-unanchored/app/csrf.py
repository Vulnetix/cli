import re

from django.http import HttpResponseForbidden


def referer_check(get_response):
    def middleware(request):
        referer = request.META.get("HTTP_REFERER", "")
~>        if request.method == "POST" and not re.match(r"https://(www\.)?acme\.com", referer):
            return HttpResponseForbidden("bad referer")
        return get_response(request)

    return middleware
