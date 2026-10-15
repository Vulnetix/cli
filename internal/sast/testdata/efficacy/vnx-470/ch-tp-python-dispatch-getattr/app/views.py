from django.http import JsonResponse

from .services import reports


def run_report(request):
    name = request.POST.get("report")
~>    handler = getattr(reports, name)
    return JsonResponse(handler(request.user))
