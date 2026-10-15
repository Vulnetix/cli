def retry(fn):
    for _ in range(3):
        for _ in range(2):
            fn()
