int trace(int m[4][4])
{
    int i, total = 0;

    for (i = 0; i < 4; i++) {
~>        for (i = 0; i < 4; i++) {
            total += m[i][i];
        }
    }
    return total;
}
