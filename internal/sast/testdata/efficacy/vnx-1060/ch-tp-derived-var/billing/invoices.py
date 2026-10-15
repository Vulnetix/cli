from django.db import connection


def invoice_lines(invoices):
    result = []
    with connection.cursor() as cursor:
        for inv in invoices:
            invoice_id = inv["id"]
~>            cursor.execute(
                "SELECT sku, qty FROM invoice_line WHERE invoice_id = %s",
                [invoice_id],
            )
            result.append(cursor.fetchall())
    return result
