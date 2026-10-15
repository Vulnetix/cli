def update(conn, sql):
    cur = conn.cursor()
    cur.execute(sql)
    cur.close()
    conn.commit()
    conn.close()


def handles(f, f2, self_obj):
    f.close()
    f2.write("x")
    file_obj = open("/tmp/x")
    file.close()
    file_obj.write("y")
