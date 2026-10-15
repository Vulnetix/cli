import sqlite3


def monthly_totals(path):
    connection = sqlite3.connect(path)
    totals = {}
    cursor = connection.cursor()
    for month in range(1, 13):
        cursor.execute(
            "SELECT SUM(amount) FROM sales WHERE month = ?",
            (month,),
        )
        totals[month] = cursor.fetchone()[0]

    cursor.close()
    return totals


def weekly(path):
    con = sqlite3.connect(path)
    try:
        c = con.cursor()
        c.execute("SELECT 1")
        return c.fetchall()
    finally:
        con.close()
