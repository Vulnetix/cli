import re

BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩]")


def strip_bidi(text: str) -> str:
    """Remove U+202E and friends before showing user names."""
    return BIDI_CONTROLS.sub("", text)
