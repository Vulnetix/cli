def retry(fn):
    for attempt in range(3):
        try:
            result = fn()
        except IOError:
            result = None
        if result is not None:
            return result
    return None


def branches(flag):
    if flag:
        value = compute_a()
    else:
        value = compute_b()
    return value


def loop(items):
    for item in items:
        current = convert(item)
        if not current:
            continue
        current = refine(item)
        emit(current)


def kwargs():
    return dict(
        timeout=compute_timeout(),
        retries=3,
    )
