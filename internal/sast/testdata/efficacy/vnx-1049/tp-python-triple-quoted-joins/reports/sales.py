from app.db import get_connection


def monthly_sales(month):
~>    sql = """
        SELECT o.id, c.name, p.title, r.region, s.name, w.code
        FROM orders o
        JOIN customers c ON c.id = o.customer_id
        JOIN order_lines l ON l.order_id = o.id
        JOIN products p ON p.id = l.product_id
        LEFT JOIN regions r ON r.id = c.region_id
        INNER JOIN salespeople s ON s.id = o.salesperson_id
        LEFT OUTER JOIN warehouses w ON w.id = l.warehouse_id
        WHERE o.month = %s
    """
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(sql, (month,))
        return cur.fetchall()
