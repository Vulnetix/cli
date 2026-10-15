def warm():
    retries = settings.RETRIES
    for _ in range(retries):
        ping()
    border = "=" * 40
