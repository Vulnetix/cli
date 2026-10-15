from django.core.files.storage import default_storage
from django.http import HttpResponse


def upload_photo(request):
    photo = request.FILES["photo"]
    if not photo.content_type.startswith("image/"):
        return HttpResponse(status=415)
~>    name = default_storage.save(f"photos/{request.user.pk}.jpg", photo)
    return HttpResponse(name)


def upload_picture(request):
    picture = request.FILES["picture"]
    with open(f"media/pictures/{picture.name}", "wb+") as dest:
~>        for chunk in picture.chunks():
            dest.write(chunk)
    return HttpResponse(status=201)
