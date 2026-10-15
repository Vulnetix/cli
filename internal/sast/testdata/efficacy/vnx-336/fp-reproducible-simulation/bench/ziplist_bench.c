#include <stdlib.h>

void bench(int *keys, int n) {
    srand(12345);
    for (int i = 0; i < n; i++) {
        int idx = rand() % n;
        keys[idx]++;
    }
}
