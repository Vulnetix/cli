import time

SCHEMA = ["CREATE TABLE a (id int)", "CREATE TABLE b (id int)"]


def init(cur):
    for statement in SCHEMA:
        cur.execute(statement)


def wait_for_db(cur):
    for attempt in range(5):
        try:
            cur.execute("SELECT 1")
            return True
        except Exception:
            time.sleep(attempt)
    return False
