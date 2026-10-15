def index_tags(posts):
    index = {}
    for pos, (slug, tags) in enumerate(posts):
        if not tags:
            continue

~>        for slug in tags:
            index.setdefault(slug, []).append(pos)
    return index
