import traceback

from django.http import HttpResponse
from django.views.decorators.http import require_GET

from .export import build_csv


@require_GET
def export_report(request, report_id):
    try:
        body = build_csv(report_id)
    except Exception:
        details = traceback.format_exc()
~>        return HttpResponse(details, status=500, content_type="text/plain")
    return HttpResponse(body, content_type="text/csv")
