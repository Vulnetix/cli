import logging

log = logging.getLogger(__name__)

# Rows are grouped by the md5 column computed by the database, see hashlib.md5 docs.
DUPLICATE_SQL = "SELECT md5(lower(email)) AS fp, count(*) FROM users GROUP BY 1 HAVING count(*) > 1"


def find_duplicates(cursor):
    cursor.execute(DUPLICATE_SQL)
    out = []
    for row in cursor.fetchall():
        record = {"md5": row[0], "count": row[1]}
        out.append(record)
    log.info("found %d duplicate groups (algorithm: %s)", len(out), "md5")
    return out
