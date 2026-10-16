def explain():
    """Calling conn.close() and then cur.execute("SELECT 1") is a bug."""
    msg = "f.close(); f.read()"
    # f.close()
    # f.read()
    return msg
