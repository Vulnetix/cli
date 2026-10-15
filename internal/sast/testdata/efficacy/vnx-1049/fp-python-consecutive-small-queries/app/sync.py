def sync(cur):
    cur.execute("SELECT a.id FROM a JOIN b ON b.a_id = a.id JOIN c ON c.b_id = b.id")
    cur.execute("SELECT d.id FROM d JOIN e ON e.d_id = d.id")
    cur.execute("SELECT f.id FROM f JOIN g ON g.f_id = f.id JOIN h ON h.g_id = g.id")
    cur.execute("SELECT i.id FROM i JOIN j ON j.i_id = i.id")
