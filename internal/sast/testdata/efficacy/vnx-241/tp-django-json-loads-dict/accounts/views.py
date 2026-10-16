import json

from django.http import JsonResponse


def rename(request):
    data = json.loads(request.body)
~>    new_name = data["name"].strip()
~>    if data.get("email").endswith("@internal.example"):
        return JsonResponse({"error": "reserved"}, status=403)
    return JsonResponse({"name": new_name})
