def drain(queues):
    for q in queues:
        if q.closed:
            for q in queues:
                q.reset()
            break
        q.flush()
