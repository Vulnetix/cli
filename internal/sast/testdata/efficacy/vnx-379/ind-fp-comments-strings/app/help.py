# Never do: open("/tmp/report.json", "w") or os.chmod(work, 0o777)
HELP = 'Avoid os.makedirs(d, mode=0o777) and logging.FileHandler("/tmp/x.log").'


def usage():
    """Writes to open("/tmp/out.txt", "w") were removed in 2.0."""
    return HELP
