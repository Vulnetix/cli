from django.http import HttpResponse


def discount(request):
    rule = request.COOKIES.get("discount_rule", "0")
~>    value = eval(rule)
    return HttpResponse(str(value))
