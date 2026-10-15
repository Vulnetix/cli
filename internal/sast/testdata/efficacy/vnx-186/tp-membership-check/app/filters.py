def reject_xss(value):
~>    if "<script" in value or "onerror=" in value:
        raise ValueError("blocked")
    return value
