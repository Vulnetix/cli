def reject_xss(value):
    lowered = value.lower()
    if "<script" in value.lower() or "onerror=" in lowered:
        raise ValueError("blocked")
    return value
