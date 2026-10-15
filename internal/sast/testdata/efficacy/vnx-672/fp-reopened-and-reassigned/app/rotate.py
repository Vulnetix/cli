def rotate(path):
    fh = open(path)
    data = fh.read()
    fh.close()
    fh = open(path + ".1", "w")
    fh.write(data)
    fh.close()


def safe(path):
    with open(path) as f:
        data = f.read()
    print(f.closed)
    return data


def checked(conn):
    conn.close()
    if conn.closed:
        return None
