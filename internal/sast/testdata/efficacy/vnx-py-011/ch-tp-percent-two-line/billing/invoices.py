import psycopg2


def delete_invoice(conn, invoice_id):
    query = "DELETE FROM invoices WHERE id = '%s'" % invoice_id
    with conn.cursor() as cur:
~>        cur.execute(query)
    conn.commit()
