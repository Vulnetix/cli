class OrderRepo:
    def __init__(self, conn):
        self.conn = conn

    def for_customer(self, customer):
        sql = "SELECT * FROM orders WHERE customer = '{}' ORDER BY created".format(customer)
        cursor = self.conn.cursor()
~>        cursor.execute(sql)
        return cursor.fetchall()

    def count(self, status):
        cursor = self.conn.cursor()
~>        cursor.execute(f"SELECT COUNT(*) FROM orders WHERE status = '{status}'")
        return cursor.fetchone()[0]
