from string import Template

from django.http import HttpResponse


def compose(request):
    body = Template("Dear $name, your order shipped.").substitute(name=request.GET["name"])
    return HttpResponse(body, content_type="text/plain")
