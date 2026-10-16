async def lines_for(conn, invoices):
    out = []
    async for inv in invoices:
        invoice_id = inv["id"]
~>        rows = await conn.fetch("SELECT sku, qty FROM invoice_line WHERE invoice_id = $1", invoice_id)
        out.append(rows)
    return out
