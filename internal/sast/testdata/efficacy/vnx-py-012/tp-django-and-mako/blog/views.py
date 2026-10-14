from django.http import HttpResponse
from django.template import Context, Template, engines


def preview(request):
~>    tpl = Template("<p>Dear " + request.GET["name"] + "</p>")
    return HttpResponse(tpl.render(Context({})))


def custom(request):
    text = request.POST.get("layout", "")
~>    t = engines["django"].from_string(text)
    return HttpResponse(t.render({}, request))
