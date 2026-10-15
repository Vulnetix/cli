from django.http import HttpResponse
from django.template import Context, Template, engines
from mako.template import Template as MakoTemplate


def preview(request):
~>    t = Template(request.GET["q"])
    return HttpResponse(t.render(Context({})))


def preview_engine(request):
    raw = request.POST.get("t", "")
~>    tpl = engines["django"].from_string(raw)
    return HttpResponse(tpl.render({}, request))


def mako_view(request):
    body = request.POST["body"]
~>    return HttpResponse(MakoTemplate(body).render())
