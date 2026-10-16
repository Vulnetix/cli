def open_shards(shards):
~>    files = [open(s, "rb") for s in shards]
    return files
