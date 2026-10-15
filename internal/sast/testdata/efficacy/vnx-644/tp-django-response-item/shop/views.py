from django.http import HttpResponse


def export(request):
    name = request.GET.get("name", "report")
    response = HttpResponse(build_csv(), content_type="text/csv")
~>    response["Content-Disposition"] = f'attachment; filename="{name}.csv"'
~>    response['X-Origin'] = request.META.get('HTTP_ORIGIN', '')
    return response
