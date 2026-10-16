from flask import abort, request

from .db import engine

~>SQL_TOKENS = ["--", "/*", "'", "union", "select"]


@app.route("/search")
def search():
    q = request.args.get("q", "")
    for tok in SQL_TOKENS:
        if tok in q.lower():
            abort(400)
    rows = engine.execute("SELECT * FROM products WHERE name LIKE '%" + q + "%'")
    return {"results": [dict(r) for r in rows]}
