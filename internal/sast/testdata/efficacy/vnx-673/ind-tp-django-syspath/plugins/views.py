import sys
from django.http import HttpResponse


def load_plugin(request):
    plugin_dir = request.GET.get("plugin_dir")
~>    sys.path.insert(0, plugin_dir)
    return HttpResponse("loaded")
