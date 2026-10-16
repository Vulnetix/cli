def outer(a):
    for x in a:
        if x:
            def inner(y):
                for z in y:
                    if z:
                        return z
            inner(x)
