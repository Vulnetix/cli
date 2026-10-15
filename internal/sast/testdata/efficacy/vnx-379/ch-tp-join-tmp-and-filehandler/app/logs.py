import logging
import os


def export(rows):
~>    with open(os.path.join("/tmp", "report.csv"), "w") as fh:
        for row in rows:
            fh.write(",".join(row) + "\n")


def configure():
~>    handler = logging.FileHandler("/tmp/service.log")
    logging.getLogger().addHandler(handler)
