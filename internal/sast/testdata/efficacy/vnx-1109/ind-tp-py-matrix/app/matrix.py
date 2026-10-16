def flatten_totals(rows):
    total = 0
    for i in range(len(rows)):
        row = rows[i]
~>        for i in range(len(row)):
            total += row[i]
        audit(rows[i])
    return total
