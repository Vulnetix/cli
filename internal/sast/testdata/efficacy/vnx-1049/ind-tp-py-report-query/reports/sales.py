from sqlalchemy import text


def sales_report(conn, year):
    query = text(
~>        '''SELECT c.id, c.name, SUM(p.amount) AS paid
        FROM customers c
        JOIN orders o ON o.customer_id = c.id
        LEFT JOIN payments p ON p.order_id = o.id
        JOIN regions r ON r.id = c.region_id
        WHERE c.id IN (SELECT customer_id FROM loyalty WHERE tier = 'gold')
          AND o.total > (SELECT AVG(total) FROM orders)
        GROUP BY c.id, c.name
        '''
    )
    return conn.execute(query, {"year": year}).fetchall()
