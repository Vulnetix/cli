from jinja2 import Environment, select_autoescape
from django.http import HttpResponse

env = Environment(autoescape=select_autoescape())


def preview(request):
    body = request.POST["body"]
~>    rendered = env.from_string(body).render(user=request.user)
    return HttpResponse(rendered)
