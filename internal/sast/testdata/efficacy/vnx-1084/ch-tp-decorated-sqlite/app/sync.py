import sqlite3


class Syncer:
    @staticmethod
    @retry(times=3)
~>    def sync(db_path, rows):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM staging")
        cur.executemany("INSERT INTO staging VALUES (?, ?)", rows)
        cur.execute("UPDATE live SET synced = 0")
        cur.execute(
            "INSERT INTO live SELECT * FROM staging"
        )
        cur.execute("DELETE FROM staging")
        cur.execute("VACUUM")
        conn.execute("ANALYZE")
        cur.executescript(open("post.sql").read())
        conn.commit()
