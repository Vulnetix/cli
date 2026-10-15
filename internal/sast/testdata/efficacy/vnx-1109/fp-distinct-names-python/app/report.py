def cells(rows):
    for i in range(len(rows)):
        for j in range(len(rows[i])):
            yield rows[i][j]
