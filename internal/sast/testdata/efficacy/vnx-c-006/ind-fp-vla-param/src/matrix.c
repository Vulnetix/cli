#include <stddef.h>

void transpose(size_t rows, size_t cols, double in[rows][cols], double out[cols][rows])
{
    for (size_t i = 0; i < rows; i++)
        for (size_t j = 0; j < cols; j++)
            out[j][i] = in[i][j];
}

double trace(size_t n, const double m[n][n])
{
    double diag[n];
    double sum = 0;
    for (size_t i = 0; i < n; i++) {
        diag[i] = m[i][i];
        sum += diag[i];
    }
    return sum;
}
