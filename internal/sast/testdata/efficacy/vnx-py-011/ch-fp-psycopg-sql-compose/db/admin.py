from psycopg2 import sql


def truncate(conn, table):
    stmt = sql.SQL("TRUNCATE {} RESTART IDENTITY").format(sql.Identifier(table))
    with conn.cursor() as cur:
        cur.execute(stmt)


def select_cols(conn, table, cols):
    q = sql.SQL("SELECT {fields} FROM {tbl}").format(
        fields=sql.SQL(", ").join(map(sql.Identifier, cols)),
        tbl=sql.Identifier(table),
    )
    with conn.cursor() as cur:
        cur.execute(q)
        return cur.fetchall()
