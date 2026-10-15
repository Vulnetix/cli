import logging

log = logging.getLogger(__name__)


def run(cur, uid):
    query = "SELECT * FROM users WHERE id = %s"
    log.debug(f"running {query} with {uid}")
    cur.execute(query, (uid,))
