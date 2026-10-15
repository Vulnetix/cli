import logging

log = logging.getLogger(__name__)


def export(rows, dest):
    log.info("not writing to /tmp/export.csv any more; using %s", dest)
    # open("/tmp/export.csv", "w") was racy
    with open(dest, "w") as fh:
        fh.writelines(rows)
