from django.core.files.storage import default_storage
from django.http import JsonResponse


def set_avatar(request):
    pic = request.FILES["avatar"]
    if not pic.content_type.startswith("image/"):
        return JsonResponse({"error": "not an image"}, status=400)
~>    path = default_storage.save("avatars/" + pic.name, pic)
    return JsonResponse({"path": path})
