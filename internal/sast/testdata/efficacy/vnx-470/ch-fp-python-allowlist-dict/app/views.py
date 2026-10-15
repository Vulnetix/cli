from django.http import JsonResponse, HttpResponseBadRequest

from .services import reports

HANDLERS = {
    "sales": reports.sales,
    "returns": reports.returns,
}


def run_report(request):
    name = request.POST.get("report")
    handler = HANDLERS.get(name)
    if handler is None:
        return HttpResponseBadRequest()
    fmt = getattr(settings, "REPORT_FORMAT", "json")
    return JsonResponse(handler(request.user))
