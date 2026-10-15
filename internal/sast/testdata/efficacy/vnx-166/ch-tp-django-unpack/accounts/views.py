from django.http import JsonResponse


def lookup(request):
~>    user, domain = request.POST["email"].split("@")
    return JsonResponse({"user": user, "domain": domain})
