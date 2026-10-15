#include <stdlib.h>
struct particle { double x; unsigned token_count; };
void step(struct particle *p, int n) {
    for (int i = 0; i < n; i++) {
        p[i].x += (double)rand() / RAND_MAX;
        p[i].token_count = rand() % 4;
    }
    int backoff_ms = 100 + rand() % 50;
    (void)backoff_ms;
}
