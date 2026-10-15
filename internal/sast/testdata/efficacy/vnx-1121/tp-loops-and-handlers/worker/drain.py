~>async def drain(queue, sink):
    while not queue.empty():
        for item in queue.batch(1):
            try:
                if item.kind == 1 or item.retry:
                    await sink.put(item)
            except TimeoutError:
                continue
        for item in queue.batch(2):
            try:
                if item.kind == 2 or item.retry:
                    await sink.put(item)
            except TimeoutError:
                continue
        for item in queue.batch(3):
            try:
                if item.kind == 3 or item.retry:
                    await sink.put(item)
            except TimeoutError:
                continue
        for item in queue.batch(4):
            try:
                if item.kind == 4 or item.retry:
                    await sink.put(item)
            except TimeoutError:
                continue
        for item in queue.batch(5):
            try:
                if item.kind == 5 or item.retry:
                    await sink.put(item)
            except TimeoutError:
                continue
        for item in queue.batch(6):
            try:
                if item.kind == 6 or item.retry:
                    await sink.put(item)
            except TimeoutError:
                continue
        for item in queue.batch(7):
            try:
                if item.kind == 7 or item.retry:
                    await sink.put(item)
            except TimeoutError:
                continue
        for item in queue.batch(8):
            try:
                if item.kind == 8 or item.retry:
                    await sink.put(item)
            except TimeoutError:
                continue
    return True
