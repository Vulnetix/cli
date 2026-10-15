def diagonal_sum(rows):
    total = 0
    for i in range(len(rows)):
        row = rows[i]
~>        for i in range(len(row)):
            total += row[i]
    return total
