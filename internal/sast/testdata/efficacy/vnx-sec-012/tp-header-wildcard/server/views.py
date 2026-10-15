from django.http import JsonResponse


def account(request):
    response = JsonResponse({"email": request.user.email})
~>    response["Access-Control-Allow-Origin"] = "*"
    return response
