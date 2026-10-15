#include <stdlib.h>
#include <time.h>

void shuffle_keys(int *keys, int n) {
    srand(time(NULL));
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = keys[i];
        keys[i] = keys[j];
        keys[j] = t;
    }
}
