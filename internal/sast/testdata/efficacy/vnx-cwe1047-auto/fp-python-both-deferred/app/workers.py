import concurrent.futures


def pool():
    return concurrent.futures.ThreadPoolExecutor(max_workers=4)


def retry(name):
    from app import jobs
    return jobs.enqueue(name)
