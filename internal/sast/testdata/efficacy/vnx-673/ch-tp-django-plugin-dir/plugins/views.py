import sys
from django.http import JsonResponse


def load_plugin(request):
    plugin_dir = request.GET.get("plugin_dir")
~>    sys.path.insert(0, plugin_dir)
    mod = __import__(request.GET["name"])
    return JsonResponse({"loaded": mod.__name__})
