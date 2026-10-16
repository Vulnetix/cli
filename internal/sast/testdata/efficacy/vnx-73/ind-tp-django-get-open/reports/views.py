from django.http import HttpResponse

REPORT_ROOT = "/srv/reports/"


def show_report(request):
    name = request.GET.get("report", "summary.txt")
~>    with open(REPORT_ROOT + name, "r", encoding="utf-8") as fh:
        content = fh.read()
    return HttpResponse(content, content_type="text/plain")
