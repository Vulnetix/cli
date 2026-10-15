def explain():
    """Explain the scoping rules.

    A name assigned in a function is local unless declared with
    global state in mind; prefer explicit parameters.
    """
    # global counter
    total = 0
    def inner():
        nonlocal total
        total += 1
    inner()
    return total
