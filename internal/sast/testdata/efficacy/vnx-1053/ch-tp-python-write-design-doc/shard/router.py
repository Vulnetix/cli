import hashlib

~># TODO: write a design doc for the sharding scheme before adding regions
def shard_for(key, shards):
    digest = hashlib.sha256(key.encode()).digest()
    return shards[digest[0] % len(shards)]
