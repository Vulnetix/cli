def check(x, false_positive):
    if false_positive:
        return 1
    if False_ish(x):
        return 2
    if 0 < x:
        return 3
    return 0
