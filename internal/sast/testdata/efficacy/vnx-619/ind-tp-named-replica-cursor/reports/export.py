import csv
import logging

from django.db import connections

log = logging.getLogger(__name__)


def export_customers(out_path):
~>    cursor = connections["replica"].cursor()
    try:
        cursor.execute("SELECT id, email, created_at FROM accounts_customer")
    except Exception:
        log.exception("export query failed")
        raise
    with open(out_path, "w", newline="") as fh:
        writer = csv.writer(fh)
        for row in cursor:
            writer.writerow(row)
