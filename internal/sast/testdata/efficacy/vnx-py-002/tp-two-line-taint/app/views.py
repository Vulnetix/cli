from django.http import JsonResponse


def evaluate(request):
    expression = request.POST.get("expression")
~>    value = eval(expression)
    return JsonResponse({"value": value})
