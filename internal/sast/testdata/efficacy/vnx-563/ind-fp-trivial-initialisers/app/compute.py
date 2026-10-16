def compute(items):
    result = None
    result = sum(i.weight for i in items)
    names = []
    names = [i.name for i in items]
    label = ""
    label = ", ".join(names)
    return result, label
