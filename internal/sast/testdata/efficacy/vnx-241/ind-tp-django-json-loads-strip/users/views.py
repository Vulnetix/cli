import json

from django.http import JsonResponse


def rename(request, user_id):
    data = json.loads(request.body)
    user = User.objects.get(pk=user_id)
~>    user.username = data["username"].strip()
    user.save()
    return JsonResponse({"username": user.username})
