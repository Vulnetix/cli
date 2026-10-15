def same(a, b, items):
    result = (
        a == b
    )
    found = any(
        x == a
        for x in items
    )
    assert a == b
    ok = a == b
    return result and found and ok and (
        a == b)


def ready(state):
    return state.ready and \
        state.count == 0


class CaseInsensitiveDict(dict):
    """A dict with case-insensitive keys.

        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
    """
