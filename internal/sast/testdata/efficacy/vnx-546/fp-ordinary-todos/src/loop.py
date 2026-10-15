def total(items):
    # TODO: refactor this loop into a comprehension
    acc = 0
    for item in items:
        acc += item.price  # FIXME: rounding
    return acc
