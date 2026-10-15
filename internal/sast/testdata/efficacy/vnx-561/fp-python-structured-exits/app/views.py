def view(request):
    if request.method == "GET":
        return list_items(request)
    elif request.method == "POST":
        return create(request)
    try:
        return fetch(request)
    except KeyError:
        return None
    finally:
        close(request)


def multi(a, b):
    return (
        a
        + b
    )


def gen(items):
    for item in items:
        if not item:
            continue
        yield item


def match(cmd):
    match cmd:
        case "start":
            return start()
        case "stop":
            return stop()
