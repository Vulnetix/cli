from flask import request

from .db import get_db


def site_settings():
    page = request.args.get("page")
    # cur.execute("SELECT * FROM invoices WHERE id = %s", (page,))
    cur = get_db().cursor()
    cur.execute("SELECT value FROM settings WHERE id = 1")
    help_text = "Run SELECT * FROM invoices WHERE id = %s to inspect one"
    return cur.fetchone(), page, help_text
