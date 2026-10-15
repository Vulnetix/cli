import sys
import site
from django.http import JsonResponse


def load_plugin(request):
    plugin_dir = request.GET.get("plugin_dir")
~>    sys.path.insert(0, plugin_dir)
~>    site.addsitedir(request.POST["site"])
    return JsonResponse({"ok": True})


def extend(request):
    data = request.get_json()
~>    sys.path.append(data["path"])
