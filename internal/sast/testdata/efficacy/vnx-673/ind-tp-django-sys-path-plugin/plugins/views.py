import importlib
import sys

from django.http import JsonResponse


def load_plugin(request):
    plugin_dir = request.GET.get("plugin_dir")
    name = request.GET.get("name", "plugin")
~>    sys.path.insert(0, plugin_dir)
    module = importlib.import_module(name)
    return JsonResponse({"loaded": module.__name__})
