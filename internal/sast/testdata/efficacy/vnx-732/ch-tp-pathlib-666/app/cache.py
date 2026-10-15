from pathlib import Path


def write_cache(data: bytes) -> Path:
    target = Path("/tmp/app-cache.bin")
    target.write_bytes(data)
~>    target.chmod(0o666)
    return target
