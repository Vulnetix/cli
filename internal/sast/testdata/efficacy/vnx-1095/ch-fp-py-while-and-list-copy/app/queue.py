def process(queue, items):
    while queue:
        job = queue.pop()
        job.run()
    for item in sorted(items):
        items.remove(item)
    for item in items:
        print(item)
    items.clear()
