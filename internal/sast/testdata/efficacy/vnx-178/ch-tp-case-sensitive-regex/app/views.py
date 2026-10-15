import re

from django.http import HttpResponseBadRequest


def upload(request):
    f = request.FILES["file"]
~>    if re.search(r"\.(php|phtml|exe)$", f.name):
        return HttpResponseBadRequest("blocked")
    handle(f)
