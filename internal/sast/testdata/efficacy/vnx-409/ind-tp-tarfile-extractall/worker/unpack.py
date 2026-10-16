import tarfile
from pathlib import Path


def unpack_dataset(archive_path: str, workdir: Path) -> Path:
    target = workdir / "dataset"
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, mode="r:*") as tar:
~>        tar.extractall(path=target, filter="data")
    return target
