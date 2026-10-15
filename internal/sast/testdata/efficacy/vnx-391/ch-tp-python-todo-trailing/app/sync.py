def sync(a, b):
    try:
        a.merge(b)
~>    except Exception:
        pass  # TODO handle conflicts
