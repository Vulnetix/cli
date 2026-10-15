from django.views.decorators.clickjacking import xframe_options_exempt
from django.http import HttpResponse

~>@xframe_options_exempt
def widget(request):
    resp = HttpResponse("ok")
~>    resp["X-Frame-Options"] = "ALLOWALL"
    return resp
