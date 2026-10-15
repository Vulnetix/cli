def lookup(key, cache):
    if key in cache:
        return cache[key]
    value = fetch(key)
    try:
        return parse(value)
    except ValueError:
        raise
    finally:
        cache[key] = value


def loop(items):
    for i in items:
        if i < 0: continue
        handle(i)
    while True:
        if done():
            break
        step()
