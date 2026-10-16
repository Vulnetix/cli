def by_status(request, cur):
    status = request.args.get("status", "open")
    allowed = {"open", "closed"}
    if status not in allowed:
        status = "open"
    cur.execute("SELECT id FROM tickets WHERE status = %s", (status,))
    return cur.fetchall()
