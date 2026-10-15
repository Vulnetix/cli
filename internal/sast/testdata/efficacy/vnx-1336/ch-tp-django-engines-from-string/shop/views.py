from django.http import HttpResponse
from django.template import engines


def banner(request):
~>    tpl = engines["django"].from_string(request.GET["msg"])
    return HttpResponse(tpl.render({}))
