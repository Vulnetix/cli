import psycopg2


class UserRepository:
    def __init__(self, dsn):
        self.conn = psycopg2.connect(dsn)

    def find(self, user_id):
~>        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cur.fetchone()

    def delete(self, user_id):
        cur = self.conn.cursor()
        try:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            self.conn.commit()
        finally:
            cur.close()
