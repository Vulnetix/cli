from pathlib import Path

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def upload_picture(request):
    picture = request.FILES["picture"]
    if not picture.content_type.startswith("image/"):
        return JsonResponse({"error": "not an image"}, status=400)
    dest = Path(settings.MEDIA_ROOT) / "pictures" / f"{request.user.pk}.jpg"
    with open(dest, "wb+") as out:
~>        for chunk in picture.chunks():
            out.write(chunk)
    return JsonResponse({"ok": True})
