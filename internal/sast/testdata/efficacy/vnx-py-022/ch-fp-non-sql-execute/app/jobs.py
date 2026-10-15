def run(executor, name):
    executor.execute(f"job-{name}")
    pool.execute("run %s" % name)
