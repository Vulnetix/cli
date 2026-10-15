from django.http import JsonResponse


def custom_metric(request):
    source = request.POST.get("snippet", "")
    scope = {"rows": load_rows(request.user)}
~>    exec(compile(source, "<metric>", "exec"), scope)
    return JsonResponse({"result": scope.get("result")})


def quick(request):
~>    return JsonResponse({"v": eval(request.GET["expr"], {"__builtins__": {}})})
