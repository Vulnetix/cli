def step(data):
    value = parse(data)
    check(value)
    value = transform(data)
    return value


def accumulate(items):
    total = compute(items)
    total = total + 1
    return total


def formatted(name):
    label = make_label(name)
    log(f"label={label}")
    label = make_label(name.upper())
    return label


def closure(x):
    handler = build(x)
    def inner():
        return handler()
    handler = build(x + 1)
    return inner
