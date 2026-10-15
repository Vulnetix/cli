from mako.template import Template as MakoTemplate
from django.template import Template, Context
from django.http import HttpResponse


def mako_view(request):
    source = request.POST.get("layout")
~>    return HttpResponse(MakoTemplate(source).render())


def django_view(request):
    body = request.GET["body"]
    text = "{% load static %}" + body
~>    return HttpResponse(Template(text).render(Context({})))
