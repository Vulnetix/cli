def merge(groups):
    merged = {}
    for key, members in groups.items():
        if not members:
            continue
        # walk the members of this group
~>        for key in members:
            merged.setdefault(key, []).append(members[key])
    return merged
