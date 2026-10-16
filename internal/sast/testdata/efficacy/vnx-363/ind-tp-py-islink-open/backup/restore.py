import os


def restore(dest: str, payload: bytes) -> None:
    if os.path.islink(dest):
        raise ValueError(f"{dest} is a symlink, refusing")
~>    with open(dest, "wb") as out:
        out.write(payload)
