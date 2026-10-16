def by_customer(cursor, customer):
    cursor.execute("SELECT * FROM orders WHERE customer = '" + customer + "'")
    return cursor.fetchall()


def by_status(cursor, status):
    cursor.execute("SELECT * FROM orders WHERE status = '%s'" % status)
    return cursor.fetchall()


def by_region(cursor, region, limit):
    cursor.execute("SELECT * FROM orders WHERE region = '{}' LIMIT {}".format(region, limit))
    return cursor.fetchall()


def bulk(cursor, table, rows):
    cursor.executemany("INSERT INTO " + table + " VALUES (?, ?)", rows)
