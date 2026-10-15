import os
from django.shortcuts import render


def blog(request):
    name = request.POST["blog"]
    try:
        here = os.path.dirname(__file__)
        target = os.path.join(here, "posts", name)
~>        with open(target, "r") as fh:
            return render(request, "blog.html", {"body": fh.read()})
    except OSError:
        return render(request, "blog.html", {"body": ""})
