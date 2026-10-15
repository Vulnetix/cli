import heapq


def merge_sorted(paths):
    handles = []
    for p in paths:
~>        handles.append(open(p, "rb"))
    return heapq.merge(*handles)


def open_shards(shards):
~>    files = [open(s) for s in shards]
    return files
