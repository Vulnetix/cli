def backfill(conn):
    conn.executescript("""
        SELECT o.id FROM orders o
        JOIN customers c ON c.id = o.customer_id
        JOIN regions r ON r.id = c.region_id
        JOIN countries k ON k.id = r.country_id;
        SELECT i.id FROM invoices i
        JOIN orders o ON o.id = i.order_id
        JOIN payments p ON p.invoice_id = i.id
        JOIN refunds f ON f.payment_id = p.id;
    """)
