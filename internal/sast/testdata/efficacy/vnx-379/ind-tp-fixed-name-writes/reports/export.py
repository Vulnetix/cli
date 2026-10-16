import io
import json


def export(report_id, payload):
~>    with open(f"/tmp/report-{report_id}.json", "w") as fh:
        json.dump(payload, fh)


AUDIT_PATH = "/var/tmp/audit.log"


def audit(line):
~>    with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def checkpoint(blob):
~>    with io.open("/dev/shm/checkpoint.bin", mode="w+b") as fh:
        fh.write(blob)
