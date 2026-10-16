import MySQLdb
import MySQLdb.cursors


def purge_sessions(cfg):
    db = MySQLdb.connect(host=cfg["host"], user=cfg["user"], passwd=cfg["pw"], db=cfg["name"])
~>    c = db.cursor(MySQLdb.cursors.DictCursor)
    c.execute("DELETE FROM sessions WHERE expires < NOW()")
    deleted = c.rowcount
    db.commit()
    print("purged", deleted)
