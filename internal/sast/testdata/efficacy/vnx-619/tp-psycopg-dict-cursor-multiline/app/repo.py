import psycopg2
import psycopg2.extras


def load_accounts(pool, region):
    conn = pool.getconn()
    try:
~>        cur = conn.cursor(
            cursor_factory=@@sample:p[s]yc[o]pg[2][.]e[x]tr[a]s[.][R]ea[l]Di[c]tC[u]rs[o]r@@
        )
        cur.execute("SELECT * FROM accounts WHERE region = %s", (region,))
        return cur.fetchall()
    finally:
        pool.putconn(conn)
