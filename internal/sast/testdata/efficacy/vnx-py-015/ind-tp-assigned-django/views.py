import re
from django.http import HttpResponse


def grep(request):
    pat = request.GET.get("pat", "")
    lines = open("log.txt").read().splitlines()
~>    hits = [l for l in lines if re.findall(pat, l)]
    return HttpResponse("\n".join(hits))
