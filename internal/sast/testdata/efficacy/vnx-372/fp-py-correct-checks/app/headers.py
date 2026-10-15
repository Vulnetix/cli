def is_json(content_type):
    if content_type.find("json") != -1:
        return True
    return False


def starts(path):
    # not s.find(x) is true only when x is at index 0: a startswith idiom
    if not path.find("/static"):
        return True
    idx = path.find("?")
    if idx >= 0:
        path = path[:idx]
    if "json" in path:
        return False
    return path.find(".") > 0
