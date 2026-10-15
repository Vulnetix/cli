import os


def append_audit(entry, log_path):
    if not os.path.isfile(log_path):
        raise RuntimeError("audit log is missing")
~>    with open(log_path, mode="a", encoding="utf-8") as fh:
        fh.write(entry + "\n")
