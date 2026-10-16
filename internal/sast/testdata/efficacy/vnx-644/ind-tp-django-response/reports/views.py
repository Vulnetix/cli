from django.http import HttpResponse

def export(request):
    name = request.GET.get("name")
    response = HttpResponse(build_csv(), content_type="text/csv")
~>    response["Content-Disposition"] = f'attachment; filename="{name}.csv"'
    return response
