#include <stdio.h>

double scale(int a, int b) {
    int q = a / 10;
    int r = a % 100;
    double inf = 1.0 / 0.0;
    double z = a / 0.5;
    int mask = a / 0x10;
    int c = a / b;
    int arr[4] = {0};
    int y = arr[0] / 2;
    return q + r + inf + z + mask + c + y;
}
