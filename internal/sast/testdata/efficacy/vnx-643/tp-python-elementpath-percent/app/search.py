import elementpath
from django.http import HttpResponse


def search(request):
    term = request.GET.get("q", "")
    expr = "//item[contains(name, '%s')]" % term
~>    hits = elementpath.select(doc, expr)
    return HttpResponse(len(hits))
