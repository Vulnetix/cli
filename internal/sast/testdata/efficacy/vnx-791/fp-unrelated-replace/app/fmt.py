def slug(title):
    title = title.replace("-", "")
    title = title.replace("\n", "")
    title = title.replace("..", "…")
    return title.replace(" ", "_")


def strip_ws(s):
    return re.sub(r"\s+", "", s)
