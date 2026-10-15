from django.http import HttpResponse


def run(request):
    code = request.POST["snippet"]
    scope = {}
~>    exec(code, scope)
    return HttpResponse(scope.get("result"))
