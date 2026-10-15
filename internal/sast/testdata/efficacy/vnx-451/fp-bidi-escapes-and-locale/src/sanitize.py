import re

# Strip Unicode bidirectional controls (Trojan Source, CVE-2021-42574).
BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069]")


def clean(text):
    return BIDI_CONTROLS.sub("", text)
