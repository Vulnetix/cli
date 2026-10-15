def open_shards(names):
~>    handles = {name: open(name, "rb") for name in names}
    return {n: h.read(16) for n, h in handles.items()}
