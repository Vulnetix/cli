#include <cstdlib>

void first() {
    char *p = new char[16];
    delete[] p;
    p = (char *)malloc(16);
    free(p);
}

void second() {
    int *q = new int[4];
    delete[] q;
}

void third(int *q) {
    free(q);
}
