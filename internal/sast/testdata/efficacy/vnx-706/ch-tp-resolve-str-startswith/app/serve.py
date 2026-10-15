from pathlib import Path

MEDIA = Path("/srv/media")


def media_path(rel):
    p = (MEDIA / rel).resolve()
~>    if not str(p).startswith(str(MEDIA)):
        raise ValueError("outside media")
    return p
