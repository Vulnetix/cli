import importlib

from django.http import HttpResponse


def export(request):
    fmt = request.GET.get("format", "csv")
~>    module = importlib.import_module(f"exporters.{fmt}")
    return HttpResponse(module.render(request.user))


def legacy(request):
~>    mod = __import__(
        request.POST["backend"],
        fromlist=["Backend"],
    )
    return HttpResponse(mod.Backend().run())
