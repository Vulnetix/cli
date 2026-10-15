from django.http import HttpResponse


def run_snippet(request):
    src = request.POST.get("source", "")
~>    code = compile(src, "<snippet>", "exec")
    scope = {}
~>    exec(code, scope)
    return HttpResponse(str(scope.get("result")))
