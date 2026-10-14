def enqueue(name):
    from app.workers import pool
    return pool().submit(name)
