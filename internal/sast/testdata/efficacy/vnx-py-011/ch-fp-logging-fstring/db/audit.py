import logging

log = logging.getLogger(__name__)

QUERY = "SELECT * FROM audit WHERE actor = %s"


def history(conn, actor):
    log.info(f"loading audit history for {actor}")
    cur = conn.cursor()
    cur.execute(QUERY, (actor,))
    print("Ran query: SELECT * FROM audit WHERE actor = '%s'" % actor)
    return cur.fetchall()
