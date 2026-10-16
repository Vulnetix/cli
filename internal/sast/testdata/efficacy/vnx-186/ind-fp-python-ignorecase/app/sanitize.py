import re

import bleach

SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
HANDLER_RE = re.compile(r"(?i)\bon(error|load|mouseover)\s*=")


def strip_scripts(value: str) -> str:
    return SCRIPT_RE.sub("", value)


def has_handler(value: str) -> bool:
    return HANDLER_RE.search(value) is not None


def is_script_url(url: str) -> bool:
    lowered = url.strip().lower()
    return lowered.startswith("javascript:")


def clean(value: str) -> str:
    cleaned = re.sub(r"<iframe.*?</iframe>", "", value, flags=re.I | re.S)
    return bleach.clean(cleaned, tags=["b", "i", "a"], strip=True)
