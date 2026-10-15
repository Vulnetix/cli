from sqlalchemy import text


def top_customers(session):
    query = text(
~>        '''SELECT c.id, c.name
        FROM customers c
        JOIN orders o ON o.customer_id = c.id
        JOIN payments p ON p.order_id = o.id
        WHERE c.id IN (SELECT customer_id FROM loyalty WHERE tier = 'gold')
          AND o.total > (SELECT AVG(total) FROM orders)
          AND p.status IN (SELECT code FROM payment_status WHERE settled = 1)
        '''
    )
    return session.execute(query).all()
