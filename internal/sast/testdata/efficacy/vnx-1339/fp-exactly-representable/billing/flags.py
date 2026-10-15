def classify(x, y):
    if x == 0.5 or x == 0.25 or x == 1.0:
        return "half"
    if y != 0.0 and y != 2.75:
        return "other"
    return x == 0.125
