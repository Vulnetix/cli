from django.http import JsonResponse

from .services import ReportService


def run_report(request):
    op = request.GET.get("op")
    service = ReportService(request.user)
~>    handler = getattr(service, op)
    return JsonResponse(handler())
