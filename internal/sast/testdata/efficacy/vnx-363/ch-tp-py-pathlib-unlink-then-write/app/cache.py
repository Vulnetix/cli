from pathlib import Path


def refresh(cache: Path, data: str) -> None:
    if cache.is_symlink():
        cache.unlink()
~>    cache.write_text(data)
