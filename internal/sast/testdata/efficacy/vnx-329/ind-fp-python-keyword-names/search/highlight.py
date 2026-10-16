def snippet(keyword: str, keys: list[str]) -> str:
    prefix = keyword[:16]
    first = keys[:16]
    return prefix + ",".join(first)
