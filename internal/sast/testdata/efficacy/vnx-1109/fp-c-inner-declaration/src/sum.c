int trace(int m[4][4])
{
    int total = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            total += m[i][j];
        }
    }
    return total;
}
