import re
import re as rx

import regex
from django.http import JsonResponse


def lookup(request):
    p = request.GET.get("p")
~>    m = regex.fullmatch(p, request.GET.get("s", ""))
~>    out = rx.sub(request.POST["find"], "", BODY)
~>    found = re.findall(
        request.GET["needle"],
        HAYSTACK,
    )
    return JsonResponse({"m": bool(m), "out": out, "found": found})
