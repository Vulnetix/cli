import redis


def warm(cluster):
    clients = []
    for node in cluster.nodes:
        clients.append(redis.Redis(host=node.host, port=node.port, db=0))
    return clients


def by_index(settings, count):
    out = []
    i = 0
    while i < count:
        cfg = settings.replicas[i]
        out.append(redis.Redis(**cfg))
        i += 1
    return out
