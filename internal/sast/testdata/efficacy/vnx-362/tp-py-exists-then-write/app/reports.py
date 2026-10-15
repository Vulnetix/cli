import os


def save_report(path, data):
    if not os.path.exists(path):
~>        with open(path, "w") as fh:
            fh.write(data)


def append_log(log_file, line):
    present = os.path.isfile(log_file)
    if present:
~>        with open(log_file, mode='a') as out:
            out.write(line)
