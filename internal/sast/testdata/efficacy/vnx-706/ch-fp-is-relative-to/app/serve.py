from pathlib import Path

MEDIA = Path("/srv/media").resolve()


def media_path(rel):
    p = (MEDIA / rel).resolve()
    if not p.is_relative_to(MEDIA):
        raise ValueError("outside media")
    return p
