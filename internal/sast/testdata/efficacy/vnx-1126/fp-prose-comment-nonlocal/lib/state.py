def make_counter():
    """Return a counter.

    global state is avoided here: the count lives in the closure.
    """
    count = 0

    def bump():
        nonlocal count
        count += 1
        return count

    # global count  -- removed, see above
    message = "global count"
    return bump, message
