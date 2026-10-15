import os

MEDIA = "/srv/media"


def media_path(requested):
~>    requested = requested.removeprefix("../")
    return os.path.join(MEDIA, requested)


def legacy_path(requested):
~>    cleaned = requested.lstrip(".\\/")
    return os.path.join(MEDIA, cleaned)
