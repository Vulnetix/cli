import os


def create_workspace(base):
    os.makedirs(os.path.join(base, "work"), mode=0o777, exist_ok=True)
    fd = os.open(
        os.path.join(base, "work", "state.json"),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o666,
    )
    with os.fdopen(fd, "w") as fh:
        fh.write("{}")
