#include <iostream>

int main()
{
    int rows;
    std::cin >> rows;
~>    double *cells = new double[rows * 8];
    delete[] cells;
    return 0;
}
