from hashlib import md5, sha1 as _sha1

from django.shortcuts import render


def register(request):
    name = request.POST.get("name")
    raw = request.POST.get("pass")
~>    stored = md5(raw.encode()).hexdigest()
~>    alt = _sha1(request.POST["password"].encode()).hexdigest()
    return render(request, "ok.html", {"name": name, "h": stored, "a": alt})
