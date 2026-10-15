MAX_DEPTH = 50


def walk(node, depth=0):
    if depth > MAX_DEPTH:
        raise ValueError("too deep")
    for child in node.children:
        walk(child, depth + 1)


def fact(n):
    if n <= 1:
        return 1
    return n * fact(n - 1)
