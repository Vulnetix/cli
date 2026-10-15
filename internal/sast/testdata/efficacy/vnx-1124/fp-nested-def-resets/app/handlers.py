def outer(items):
    for item in items:
        if item:
            def inner(x):
                for y in x:
                    if y:
                        for z in y:
                            if z:
                                return z
            inner(item)
