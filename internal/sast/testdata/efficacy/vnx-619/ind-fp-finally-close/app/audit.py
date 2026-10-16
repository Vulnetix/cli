import mysql.connector


def record_event(cfg, actor, action):
    cnx = mysql.connector.connect(**cfg)
    cur = cnx.cursor()
    try:
        cur.execute(
            "INSERT INTO audit_log (actor, action) VALUES (%s, %s)",
            (actor, action),
        )
        cnx.commit()
    finally:
        cur.close()
        cnx.close()
