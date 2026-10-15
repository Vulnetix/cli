#include <stdlib.h>

void place_enemies(int level, int *xs, int n, int width) {
    srand(level % 10);
    for (int i = 0; i < n; i++) {
        xs[i] = rand() % width;
    }
}
